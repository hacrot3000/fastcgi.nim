
const
  FCGI_MAX_LENGTH*    = 0xffff
  FCGI_HEADER_LENGTH* = 8
  FCGI_VERSION_1*     = 1'u8       ## Fix #11: typed as uint8 to match wire format

  FCGI_KEEP_CONNECTION* = 1'u8     ## Typo fixed: FGCI -> FCGI

  ## Fix #1: application request ID must be 1, never 0
  FCGI_REQUEST_ID* = 1'u16

  FCGI_MAX_CONNS*  = "FCGI_MAX_CONNS"
  FCGI_MAX_REQS*   = "FCGI_MAX_REQS"
  FCGI_MPXS_CONNS* = "FCGI_MPXS_CONNS"

  ## Wire record types as uint8 (Fix #1)
  FCGI_BEGIN_REQUEST*     = 1'u8
  FCGI_ABORT_REQUEST*     = 2'u8
  FCGI_END_REQUEST*       = 3'u8
  FCGI_PARAMS*            = 4'u8
  FCGI_STDIN*             = 5'u8
  FCGI_STDOUT*            = 6'u8
  FCGI_STDERR*            = 7'u8
  FCGI_DATA*              = 8'u8
  FCGI_GET_VALUES*        = 9'u8
  FCGI_GET_VALUES_RESULT* = 10'u8
  FCGI_UNKNOWN_TYPE*      = 11'u8

type
  FastCgiTimeoutError* = object of CatchableError

  FCGI_ROLE* = enum
    FCGI_RESPONDER  = 1
    FCGI_AUTHORIZER = 2
    FCGI_FILTER     = 3

  ProtocolStatus* = enum
    FCGI_REQUEST_COMPLETE = 0
    FCGI_CANT_MPX_CONN    = 1
    FCGI_OVERLOADED       = 2
    FCGI_UNKNOWN_ROLE     = 3

  ## Fix: {.packed.} ensures no struct padding on any platform.
  ## Fix #1: kind is uint8 on wire rather than enum to avoid range/runtime crash.
  Header* {.packed.} = object
    version*:          uint8
    kind*:             uint8
    requestIdB1*:      uint8
    requestIdB0*:      uint8
    contentLengthB1*:  uint8
    contentLengthB0*:  uint8
    paddingLength*:    uint8
    reserved*:         uint8

  BeginRequestBody* {.packed.} = object
    roleB1*:   uint8
    roleB0*:   uint8
    flags*:    uint8
    reserved*: array[5, uint8]

  BeginRequestRecord* {.packed.} = object
    header*: Header
    body*:   BeginRequestBody

  EndRequestBody* {.packed.} = object
    appStatusB3*:    uint8
    appStatusB2*:    uint8
    appStatusB1*:    uint8
    appStatusB0*:    uint8
    protocolStatus*: uint8
    reserved*:       array[3, uint8]   ## Fix: use uint8, not char

  EndRequestRecord* {.packed.} = object
    header*: Header
    body*:   EndRequestBody

  UnknownTypeBody* {.packed.} = object
    kind*:     uint8
    reserved*: array[7, uint8]

  UnknownTypeRecord* {.packed.} = object
    header*: Header
    body*:   UnknownTypeBody

  ## Public result types for callPhpFastcgi API (Fix #18)
  PhpHeader* = tuple[name: string, value: string]

  PhpCallResult* = object
    transportOk*:    bool             ## Fix #4: true if FastCGI transport completed successfully
    ok*:             bool             ## Fix #4: transportOk and appStatus == 0 and statusCode in 2xx
    statusCode*:     int
    headers*:        seq[PhpHeader]
    body*:           string
    stderr*:         string           ## Fix #5: separate stderr
    appStatus*:      int32            ## Fix #13: parsed from FCGI_END_REQUEST
    protocolStatus*: int              ## Fix #13,14
    error*:          string

  PhpFastCgiConfig* = object
    host*:             string
    port*:             int
    documentRoot*:     string
    serverName*:       string
    connectTimeoutMs*: int   ## Fix #3 – 0 = 3000 ms default fallback
    readTimeoutMs*:    int   ## Fix #3 – per-recv timeout; 0 = 5000 ms default fallback
    writeTimeoutMs*:   int   ## Fix #3 – per-send timeout; 0 = 5000 ms default fallback
    totalTimeoutMs*:   int   ## Fix #3 – wall-clock cap for full call; 0 = 30,000 ms
    maxStdoutBytes*:   int   ## Fix #15 – OOM guard; 0 = 32 MiB
    maxStderrBytes*:   int   ## Fix #15 – OOM guard; 0 = 256 KiB

# ---------------------------------------------------------------------------
# Static asserts (Fix #8)
# ---------------------------------------------------------------------------

static:
  doAssert sizeof(Header) == 8
  doAssert sizeof(BeginRequestBody) == 8
  doAssert sizeof(BeginRequestRecord) == 16
  doAssert sizeof(EndRequestBody) == 8

# ---------------------------------------------------------------------------
# Helper procs
# ---------------------------------------------------------------------------

proc initHeader*(kind: uint8, reqId: uint16,
                 contentLength, paddingLength: int): Header =
  result.version         = FCGI_VERSION_1
  result.kind            = kind
  ## Fix #1: reqId is passed by caller; callees must pass FCGI_REQUEST_ID (=1)
  result.requestIdB1     = uint8((reqId shr 8) and 0xff)
  result.requestIdB0     = uint8(reqId and 0xff)
  result.contentLengthB1 = uint8((contentLength shr 8) and 0xff)
  result.contentLengthB0 = uint8(contentLength and 0xff)
  result.paddingLength   = paddingLength.uint8
  result.reserved        = 0

proc initBeginRequestBody*(role: FCGI_ROLE, keepalive: bool): BeginRequestBody =
  result.roleB1 = uint8((role.int shr 8) and 0xff)
  result.roleB0 = uint8(role.int and 0xff)
  result.flags  = if keepalive: FCGI_KEEP_CONNECTION else: 0

proc initEndRequestBody*(appStatus: int32,
                         status = FCGI_REQUEST_COMPLETE): EndRequestBody =
  result.appStatusB3     = uint8((appStatus shr 24) and 0xff)
  result.appStatusB2     = uint8((appStatus shr 16) and 0xff)
  result.appStatusB1     = uint8((appStatus shr 8)  and 0xff)
  result.appStatusB0     = uint8(appStatus           and 0xff)
  result.protocolStatus  = status.uint8

## Decode appStatus from a parsed EndRequestBody
proc decodeAppStatus*(b: EndRequestBody): int32 =
  (b.appStatusB3.int32 shl 24) or
  (b.appStatusB2.int32 shl 16) or
  (b.appStatusB1.int32 shl 8)  or
   b.appStatusB0.int32

## Content-length field of a Header
proc contentLen*(h: Header): int =
  (h.contentLengthB1.int shl 8) or h.contentLengthB0.int

## requestId field of a Header
proc requestId*(h: Header): uint16 =
  (h.requestIdB1.uint16 shl 8) or h.requestIdB0.uint16

proc defaultPhpFastCgiConfig*(
  host:         string = "127.0.0.1",
  port:         int    = 19090,
  documentRoot: string = "/var/www/html",
  serverName:   string = "localhost"
): PhpFastCgiConfig =
  result.host              = host
  result.port              = port
  result.documentRoot      = documentRoot
  result.serverName        = serverName
  result.connectTimeoutMs  = 3_000
  result.readTimeoutMs     = 5_000
  result.writeTimeoutMs    = 5_000
  result.totalTimeoutMs    = 30_000
  result.maxStdoutBytes    = 32 * 1024 * 1024
  result.maxStderrBytes    = 256 * 1024