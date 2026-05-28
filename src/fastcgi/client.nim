import std/[net, strutils, parseutils, times]
import posix
import private/common

export common.PhpHeader, common.PhpCallResult, common.PhpFastCgiConfig
export common.defaultPhpFastCgiConfig
export common.ProtocolStatus
export common.FCGI_BEGIN_REQUEST, common.FCGI_ABORT_REQUEST, common.FCGI_END_REQUEST
export common.FCGI_PARAMS, common.FCGI_STDIN, common.FCGI_STDOUT, common.FCGI_STDERR
export common.FCGI_DATA, common.FCGI_GET_VALUES, common.FCGI_GET_VALUES_RESULT
export common.FCGI_UNKNOWN_TYPE
export common.FastCgiTimeoutError

# ---------------------------------------------------------------------------
# Low-level I/O helpers with deadline enforcement
# ---------------------------------------------------------------------------

proc ensureNotExpired(deadline: times.Time) =
  if getTime() > deadline:
    raise newException(FastCgiTimeoutError, "FastCGI total timeout exceeded")

## Fix #2: recv exactly n bytes – loops on short reads
proc recvExact(sock: Socket, dst: pointer, n: int, deadline: times.Time) =
  if n == 0: return
  var received = 0
  let p = cast[ptr UncheckedArray[uint8]](dst)
  while received < n:
    ensureNotExpired(deadline)
    let got = sock.recv(cast[pointer](addr p[received]), n - received)
    if got <= 0:
      raise newException(IOError,
        "recvExact: connection closed (needed " & $n &
        ", received " & $received & ")")
    received += got

## Fix #2: send exactly n bytes – loops on short writes
proc sendAll(sock: Socket, src: pointer, n: int, deadline: times.Time) =
  if n == 0: return
  var sent = 0
  let p = cast[ptr UncheckedArray[uint8]](src)
  while sent < n:
    ensureNotExpired(deadline)
    let wrote = sock.send(cast[pointer](addr p[sent]), n - sent)
    if wrote <= 0:
      raise newException(IOError,
        "sendAll: send failed (needed " & $n & ", sent " & $sent & ")")
    sent += wrote

## Fix #10: drain exactly paddingLen bytes regardless of value
proc drainPadding(sock: Socket, paddingLen: int, deadline: times.Time) =
  if paddingLen <= 0: return
  var buf: array[256, uint8]
  var remaining = paddingLen
  while remaining > 0:
    let chunk = min(remaining, 256)
    recvExact(sock, addr buf[0], chunk, deadline)
    remaining -= chunk

# ---------------------------------------------------------------------------
# FCGI NV-pair encoder
# ---------------------------------------------------------------------------

proc encodeNvPair(name, value: string): string =
  let nl = name.len
  let vl = value.len
  var buf = newStringOfCap(nl + vl + 8)

  if nl < 128:
    buf.add chr(nl)
  else:
    buf.add chr(((nl shr 24) and 0x7f) or 0x80)
    buf.add chr((nl shr 16) and 0xff)
    buf.add chr((nl shr 8)  and 0xff)
    buf.add chr( nl         and 0xff)

  if vl < 128:
    buf.add chr(vl)
  else:
    buf.add chr(((vl shr 24) and 0x7f) or 0x80)
    buf.add chr((vl shr 16) and 0xff)
    buf.add chr((vl shr 8)  and 0xff)
    buf.add chr( vl         and 0xff)

  buf.add name
  buf.add value
  result = buf

# ---------------------------------------------------------------------------
# Send helpers
# ---------------------------------------------------------------------------

## Fix #1: pass FCGI_REQUEST_ID (=1) as requestId
proc sendBeginRequest(sock: Socket, keepalive: bool, deadline: times.Time) =
  var rec: BeginRequestRecord
  rec.header = initHeader(FCGI_BEGIN_REQUEST, FCGI_REQUEST_ID,
                           sizeof(BeginRequestBody), 0)
  rec.body   = initBeginRequestBody(FCGI_RESPONDER, keepalive)
  sendAll(sock, addr rec, sizeof(rec), deadline)

## Fix #6,#7: chunk params across multiple records, then send empty terminator
proc sendParams(sock: Socket, params: openArray[(string, string)], deadline: times.Time) =
  var blob = newStringOfCap(4096)
  for (k, v) in params:
    if k.len == 0: continue
    blob.add encodeNvPair(k, v)

  var offset = 0
  while offset < blob.len:
    let chunk = min(blob.len - offset, FCGI_MAX_LENGTH)
    var hdr = initHeader(FCGI_PARAMS, FCGI_REQUEST_ID, chunk, 0)
    sendAll(sock, addr hdr, sizeof(hdr), deadline)
    sendAll(sock, cast[pointer](unsafeAddr blob[offset]), chunk, deadline)
    offset += chunk

  # Fix #7: empty FCGI_PARAMS signals end of params
  var endHdr = initHeader(FCGI_PARAMS, FCGI_REQUEST_ID, 0, 0)
  sendAll(sock, addr endHdr, sizeof(endHdr), deadline)

## Fix #6,#8: chunk stdin across multiple records, then send empty terminator
proc sendStdin(sock: Socket, body: string, deadline: times.Time) =
  var offset = 0
  while offset < body.len:
    let chunk = min(body.len - offset, FCGI_MAX_LENGTH)
    var hdr = initHeader(FCGI_STDIN, FCGI_REQUEST_ID, chunk, 0)
    sendAll(sock, addr hdr, sizeof(hdr), deadline)
    sendAll(sock, cast[pointer](unsafeAddr body[offset]), chunk, deadline)
    offset += chunk

  # Fix #8: empty FCGI_STDIN signals end of body
  var endHdr = initHeader(FCGI_STDIN, FCGI_REQUEST_ID, 0, 0)
  sendAll(sock, addr endHdr, sizeof(endHdr), deadline)

# ---------------------------------------------------------------------------
# Read response
# ---------------------------------------------------------------------------

type ReadState = object
  stdout:         string
  stderr:         string
  appStatus:      int32
  protocolStatus: int
  done:           bool

proc readResponse(sock: Socket, maxStdout, maxStderr: int, deadline: times.Time): ReadState =
  result.stdout = ""
  result.stderr = ""
  result.done   = false

  while not result.done:
    ensureNotExpired(deadline)
    var hdr: Header
    recvExact(sock, addr hdr, FCGI_HEADER_LENGTH, deadline)

    # Fix #11: version must be 1
    if hdr.version != FCGI_VERSION_1:
      raise newException(IOError,
        "FCGI: bad version " & $hdr.version & " (expected 1)")

    # Fix #12: requestId must match what we sent
    if hdr.requestId() != FCGI_REQUEST_ID:
      raise newException(IOError,
        "FCGI: requestId mismatch (got " & $hdr.requestId() &
        ", expected " & $FCGI_REQUEST_ID & ")")

    let cLen = hdr.contentLen()
    let pLen = hdr.paddingLength.int

    case hdr.kind

    of FCGI_STDOUT:
      # Fix #4: append, never overwrite
      if cLen > 0:
        # Fix #15: OOM guard
        if result.stdout.len + cLen > maxStdout:
          raise newException(IOError,
            "FCGI_STDOUT exceeded maxStdoutBytes (" & $maxStdout & ")")
        let prev = result.stdout.len
        result.stdout.setLen(prev + cLen)
        recvExact(sock, cast[pointer](unsafeAddr result.stdout[prev]), cLen, deadline)
      drainPadding(sock, pLen, deadline)  # Fix #10

    of FCGI_STDERR:
      # Fix #5: separate stderr buffer
      if cLen > 0:
        # Fix #15: OOM guard
        if result.stderr.len + cLen > maxStderr:
          raise newException(IOError,
            "FCGI_STDERR exceeded maxStderrBytes (" & $maxStderr & ")")
        let prev = result.stderr.len
        result.stderr.setLen(prev + cLen)
        recvExact(sock, cast[pointer](unsafeAddr result.stderr[prev]), cLen, deadline)
      drainPadding(sock, pLen, deadline)  # Fix #10

    of FCGI_END_REQUEST:
      # Fix #13: parse full EndRequestBody
      if cLen < sizeof(EndRequestBody):
        raise newException(IOError,
          "FCGI_END_REQUEST body too short: " & $cLen)
      var endBody: EndRequestBody
      recvExact(sock, addr endBody, sizeof(endBody), deadline)
      # drain any extra bytes beyond the struct
      let extra = cLen - sizeof(endBody)
      if extra > 0:
        var tmp = newString(extra)
        recvExact(sock, cast[pointer](unsafeAddr tmp[0]), extra, deadline)
      drainPadding(sock, pLen, deadline)  # Fix #10

      result.appStatus      = decodeAppStatus(endBody)
      result.protocolStatus = endBody.protocolStatus.int
      result.done           = true

    else:
      # Fix #9: unknown record type – drain to keep stream aligned
      if cLen > 0:
        var tmp = newString(cLen)
        recvExact(sock, cast[pointer](unsafeAddr tmp[0]), cLen, deadline)
      drainPadding(sock, pLen, deadline)  # Fix #10

# ---------------------------------------------------------------------------
# Fix #16: parse raw PHP CGI stdout into statusCode, headers, body
# ---------------------------------------------------------------------------

proc parsePhpResponse(raw: string): tuple[
    status: int, headers: seq[PhpHeader], body: string] =
  result.status  = 200
  result.headers = @[]
  result.body    = ""

  if raw.len == 0:
    return

  # find header / body separator (CRLF preferred, LF fallback)
  let sepCRLF = raw.find("\r\n\r\n")
  let sepLF   = raw.find("\n\n")

  var headerSection: string
  var bodyStart: int

  if sepCRLF >= 0 and (sepLF < 0 or sepCRLF <= sepLF):
    headerSection = raw[0 ..< sepCRLF]
    bodyStart     = sepCRLF + 4
  elif sepLF >= 0:
    headerSection = raw[0 ..< sepLF]
    bodyStart     = sepLF + 2
  else:
    result.body = raw
    return

  if bodyStart < raw.len:
    result.body = raw[bodyStart .. ^1]
  else:
    result.body = ""

  for line in headerSection.splitLines():
    let trimmed = line.strip()
    if trimmed.len == 0: continue
    let colon = trimmed.find(':')
    if colon < 0: continue
    let name  = trimmed[0 ..< colon].strip()
    let value = trimmed[colon + 1 .. ^1].strip()
    # CGI "Status:" pseudo-header
    if name.cmpIgnoreCase("Status") == 0:
      var code = 0
      try:
        discard parseInt(value, code)
        if code > 0: result.status = code
      except ValueError:
        discard  # malformed Status line – keep default 200
    else:
      result.headers.add((name, value))

# ---------------------------------------------------------------------------
# Fix #3: apply per-socket read/write timeouts via SO_RCVTIMEO/SO_SNDTIMEO
# ---------------------------------------------------------------------------

proc applyTimeouts(sock: Socket, cfg: PhpFastCgiConfig, totalMs: int) =
  # Enforce non-zero timeout safety values for production GM
  let rawReadMs  = if cfg.readTimeoutMs > 0: cfg.readTimeoutMs else: 5_000
  let rawWriteMs = if cfg.writeTimeoutMs > 0: cfg.writeTimeoutMs else: 5_000

  let rTimeoutMs = min(rawReadMs, totalMs)
  let wTimeoutMs = min(rawWriteMs, totalMs)

  var tvR: Timeval
  tvR.tv_sec  = posix.Time(rTimeoutMs div 1000)
  tvR.tv_usec = Suseconds((rTimeoutMs mod 1000) * 1000)
  let rcR = setsockopt(sock.getFd(), SOL_SOCKET.cint, SO_RCVTIMEO.cint,
                      addr tvR, SockLen(sizeof(tvR)))
  if rcR != 0:
    raise newException(OSError, "setsockopt SO_RCVTIMEO failed")

  var tvW: Timeval
  tvW.tv_sec  = posix.Time(wTimeoutMs div 1000)
  tvW.tv_usec = Suseconds((wTimeoutMs mod 1000) * 1000)
  let rcW = setsockopt(sock.getFd(), SOL_SOCKET.cint, SO_SNDTIMEO.cint,
                      addr tvW, SockLen(sizeof(tvW)))
  if rcW != 0:
    raise newException(OSError, "setsockopt SO_SNDTIMEO failed")

# ---------------------------------------------------------------------------
# Validating normalizations (Fix #5, #3)
# ---------------------------------------------------------------------------

proc normalizeScriptName(scriptName: string): string =
  var s = scriptName.strip()
  s = s.replace("\\", "/")
  s = s.strip(chars = {'/'})

  if s.len == 0:
    raise newException(ValueError, "empty scriptName")

  if s.contains(".."):
    raise newException(ValueError, "scriptName must not contain '..'")

  result = "/" & s

proc normalizeDocumentRoot(documentRoot: string): string =
  var d = documentRoot.strip()
  d = d.replace("\\", "/")
  d = d.strip(chars = {'/'}, trailing = true, leading = false)

  if d.len == 0:
    raise newException(ValueError, "empty documentRoot")

  if not d.startsWith("/"):
    raise newException(ValueError, "documentRoot must be absolute path")

  if d.contains(".."):
    raise newException(ValueError, "documentRoot must not contain '..'")

  result = d

# ---------------------------------------------------------------------------
# Reserved Parameter list (Fix #4)
# ---------------------------------------------------------------------------

const ReservedParams = [
  "SCRIPT_FILENAME",
  "SCRIPT_NAME",
  "DOCUMENT_ROOT",
  "DOCUMENT_URI",
  "REQUEST_URI",
  "QUERY_STRING",
  "REQUEST_METHOD",
  "CONTENT_TYPE",
  "CONTENT_LENGTH",
  "SERVER_PROTOCOL",
  "SERVER_SOFTWARE",
  "SERVER_NAME",
  "SERVER_ADDR",
  "SERVER_PORT",
  "REMOTE_ADDR",
  "REMOTE_PORT",
  "GATEWAY_INTERFACE",
  "PHP_VALUE",
  "PHP_ADMIN_VALUE"
]

# ---------------------------------------------------------------------------
# Fix #18: public high-level API
# ---------------------------------------------------------------------------

proc callPhpFastcgi*(
  cfg:         PhpFastCgiConfig,
  scriptName:  string,
  requestUri:  string,
  queryString: string,
  body:        string,
  meth:        string = "POST",
  contentType: string = "application/json",
  extraParams: openArray[(string, string)] = []
): PhpCallResult =
  ## Perform one FastCGI request. Opens a fresh TCP connection, sends the
  ## request, reads the full response, then closes the socket regardless of
  ## outcome. Blocking – run in a dedicated thread, never the main GM event loop.
  ##
  ## HTTPS note: if your gateway receives requests over HTTPS, pass
  ## extraParams = [("HTTPS", "on")] so PHP-FPM generates correct redirect URLs.

  let maxStdout = if cfg.maxStdoutBytes > 0: cfg.maxStdoutBytes
                  else: 32 * 1024 * 1024   # 32 MiB
  let maxStderr = if cfg.maxStderrBytes > 0: cfg.maxStderrBytes
                  else: 256 * 1024          # 256 KiB

  # Fix #3: total deadline
  let totalMs   = if cfg.totalTimeoutMs > 0: cfg.totalTimeoutMs else: 30_000
  let deadline  = getTime() + initDuration(milliseconds = totalMs)
  let rawConnMs = if cfg.connectTimeoutMs > 0: cfg.connectTimeoutMs else: 3_000
  let connMs    = min(rawConnMs, totalMs)

  # Validate host and port
  if cfg.host.strip().len == 0:
    raise newException(ValueError, "empty FastCGI proxy host")
  if cfg.port <= 0 or cfg.port > 65535:
    raise newException(ValueError, "invalid FastCGI proxy port: " & $cfg.port)

  var sock: Socket = nil
  try:
    # Normalize script and document root
    let sn = normalizeScriptName(scriptName)
    let docRoot = normalizeDocumentRoot(cfg.documentRoot)
    let scriptFilename = docRoot & sn

    # Uppercase request method and throw if empty (Fix #6)
    let methodUpper = meth.strip().toUpperAscii()
    if methodUpper.len == 0:
      raise newException(ValueError, "empty REQUEST_METHOD")

    # Build requestUri automatically if empty (Fix #5)
    let requestUriClean = requestUri.strip()
    let reqUri =
      if requestUriClean.len > 0:
        requestUriClean
      elif queryString.len > 0:
        sn & "?" & queryString
      else:
        sn
    if not reqUri.startsWith("/"):
      raise newException(ValueError, "REQUEST_URI must start with '/'")

    sock = newSocket()
    # Apply TCP_NODELAY (Fix #8)
    sock.setSockOpt(OptNoDelay, true)
    applyTimeouts(sock, cfg, totalMs)
    sock.connect(cfg.host, Port(cfg.port), timeout = connMs)
    ensureNotExpired(deadline)

    sendBeginRequest(sock, keepalive = false, deadline)

    var params: seq[(string, string)] = @[
      ("SCRIPT_FILENAME",   scriptFilename),
      ("SCRIPT_NAME",       sn),
      ("DOCUMENT_ROOT",     docRoot),
      ("DOCUMENT_URI",      sn),
      ("REQUEST_URI",       reqUri),
      ("QUERY_STRING",      queryString),
      ("REQUEST_METHOD",    methodUpper),
      ("SERVER_PROTOCOL",   "HTTP/1.1"),
      ("SERVER_SOFTWARE",   "ss20-gm"),
      ("SERVER_NAME",       cfg.serverName),
      ("SERVER_ADDR",       "127.0.0.1"),
      ("SERVER_PORT",       $cfg.port),
      ("REMOTE_ADDR",       "127.0.0.1"),
      ("REMOTE_PORT",       "0"),
      ("GATEWAY_INTERFACE", "CGI/1.1"),
    ]
    # Add Content type/length if body exists (Fix #11)
    let ct = if contentType.strip().len > 0: contentType.strip() else: "application/octet-stream"
    if body.len > 0:
      params.add(("CONTENT_TYPE", ct))
      params.add(("CONTENT_LENGTH", $body.len))
    else:
      params.add(("CONTENT_LENGTH", "0"))

    # Add extraParams checking against reserved parameters
    for kv in extraParams:
      let key = kv[0].strip()
      let k = key.toUpperAscii()
      if key.len == 0:
        raise newException(ValueError, "extraParams contains empty key")
      if k in ReservedParams:
        raise newException(ValueError, "extraParams must not override reserved param: " & key)
      params.add((key, kv[1]))

    sendParams(sock, params, deadline)
    sendStdin(sock, body, deadline)

    let state = readResponse(sock, maxStdout, maxStderr, deadline)
    let (status, headers, respBody) = parsePhpResponse(state.stdout)

    result.statusCode     = status
    result.headers        = headers
    result.body           = respBody
    result.stderr         = state.stderr
    result.appStatus      = state.appStatus
    result.protocolStatus = state.protocolStatus

    # Fix #4: define ok and transportOk
    if state.protocolStatus != FCGI_REQUEST_COMPLETE.int:
      result.transportOk = false
      result.ok          = false
      result.error       = "FCGI protocolStatus: " & $state.protocolStatus
    else:
      result.transportOk = true
      result.ok          = (state.appStatus == 0) and (status >= 200 and status < 300)
      if state.appStatus != 0:
        result.error = "FCGI appStatus: " & $state.appStatus
      elif not (status >= 200 and status < 300):
        result.error = "PHP HTTP status: " & $status

  except FastCgiTimeoutError as e:
    result.transportOk = false
    result.ok          = false
    result.error       = "timeout: " & e.msg
  except IOError as e:
    result.transportOk = false
    result.ok          = false
    result.error       = "io: " & e.msg
  except OSError as e:
    result.transportOk = false
    result.ok          = false
    # EAGAIN/EWOULDBLOCK (errno 11) means SO_RCVTIMEO/SO_SNDTIMEO expired inside recv/send.
    # Distinguish it from a genuine network error so GM logs are unambiguous.
    if e.errorCode == EAGAIN or
       e.msg.contains("Resource temporarily unavailable") or
       e.msg.contains("timed out"):
      result.error = "timeout (os): PHP-FPM/proxy did not respond in time"
    else:
      result.error = "os: " & e.msg
  except Exception as e:
    result.transportOk = false
    result.ok          = false
    result.error       = "exception[" & $e.name & "]: " & e.msg
  finally:
    # Fix #17: always close socket
    if sock != nil:
      try: sock.close() except: discard