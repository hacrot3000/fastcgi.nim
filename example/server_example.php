<?php
/**
 * PHP External Proxy Server Example
 * Receives and processes requests forwarded by the Nim external proxy module.
 *
 * Wire format (all big-endian):
 *   [1 byte  mode: 0x01=full 0x02=userId]
 *   [AMF3 payload (variable)]
 *   [4 bytes raw packet length (uint32 BE)]
 *   [N bytes raw packet bytes]
 *   [4 bytes CRC32 of everything above this field (uint32 BE)]
 */

// Define log file path
define('LOG_FILE', __DIR__ . '/../../logs/proxy_server.log');

// Helper function to log messages
function writeLog($msg, $level = 'INFO') {
    $date = date('Y-m-d H:i:s');
    $logMsg = "[{$date}] [{$level}] {$msg}\n";
    file_put_contents(LOG_FILE, $logMsg, FILE_APPEND);
}

// -------------------------------------------------------------------------
// AMF3 Decoder Implementation
// -------------------------------------------------------------------------
class Amf3Reader {
    private $data;
    private $pos;

    public function __construct($data, $startPos = 0) {
        $this->data = $data;
        $this->pos = $startPos;
    }

    public function getPos() {
        return $this->pos;
    }

    public function readU29() {
        $result = 0;
        for ($i = 0; $i < 4; $i++) {
            if ($this->pos >= strlen($this->data)) {
                throw new Exception("AMF3 EOF U29");
            }
            $b = ord($this->data[$this->pos++]);
            if ($i < 3) {
                $result = ($result << 7) | ($b & 0x7f);
                if (($b & 0x80) == 0) {
                    return $result;
                }
            } else {
                $result = ($result << 8) | $b;
                return $result;
            }
        }
        return $result;
    }

    public function readDouble() {
        if ($this->pos + 8 > strlen($this->data)) {
            throw new Exception("AMF3 EOF Double");
        }
        $bytes = substr($this->data, $this->pos, 8);
        $this->pos += 8;
        $unpacked = unpack("E", $bytes); // BE double format
        return $unpacked[1];
    }

    public function readString() {
        $header = $this->readU29();
        if (($header & 1) == 0) {
            throw new Exception("AMF3 String reference not supported");
        }
        $len = $header >> 1;
        if ($this->pos + $len > strlen($this->data)) {
            throw new Exception("AMF3 EOF String");
        }
        $s = substr($this->data, $this->pos, $len);
        $this->pos += $len;
        return $s;
    }

    public function readValue() {
        if ($this->pos >= strlen($this->data)) {
            throw new Exception("AMF3 EOF Marker");
        }
        $marker = ord($this->data[$this->pos++]);
        switch ($marker) {
            case 0x01: // Null
                return null;
            case 0x02: // False
                return false;
            case 0x03: // True
                return true;
            case 0x04: // Integer
                $val = $this->readU29();
                // Sign extend 29-bit integer
                if (($val & 0x10000000) != 0) {
                    $val = $val - 0x20000000;
                }
                return $val;
            case 0x05: // Double
                return $this->readDouble();
            case 0x06: // String
                return $this->readString();
            case 0x09: // Array
                $header = $this->readU29();
                if (($header & 1) == 0) {
                    throw new Exception("AMF3 Array reference not supported");
                }
                $count = $header >> 1;
                $assoc = [];
                while (true) {
                    $key = $this->readString();
                    if ($key === "") {
                        break;
                    }
                    $assoc[$key] = $this->readValue();
                }
                $dense = [];
                for ($i = 0; $i < $count; $i++) {
                    $dense[] = $this->readValue();
                }
                return empty($assoc) ? $dense : array_merge($assoc, $dense);
            case 0x0A: // Object
                $header = $this->readU29();
                if (($header & 1) == 0) {
                    throw new Exception("AMF3 Object reference not supported");
                }
                if (($header & 2) == 0) {
                    throw new Exception("AMF3 Trait reference not supported");
                }
                $externalizable = ($header & 4) !== 0;
                $dynamic = ($header & 8) !== 0;
                $sealedCount = $header >> 4;
                if ($externalizable) {
                    throw new Exception("AMF3 Externalizable not supported");
                }
                $className = $this->readString();
                $sealedNames = [];
                for ($i = 0; $i < $sealedCount; $i++) {
                    $sealedNames[] = $this->readString();
                }
                $obj = [];
                foreach ($sealedNames as $name) {
                    $obj[$name] = $this->readValue();
                }
                if ($dynamic) {
                    while (true) {
                        $key = $this->readString();
                        if ($key === "") {
                            break;
                        }
                        $obj[$key] = $this->readValue();
                    }
                }
                return $obj;
            default:
                throw new Exception("Unsupported AMF3 marker: 0x" . dechex($marker));
        }
    }
}

// -------------------------------------------------------------------------
// Main Request Handling
// -------------------------------------------------------------------------
try {
    // Ensure logs folder exists
    $logDir = dirname(LOG_FILE);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0777, true);
    }

    $msgId = isset($_GET['msgId']) ? intval($_GET['msgId']) : 0;
    $clientIp = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    
    writeLog("Received request for msgId: {$msgId} from IP: {$clientIp}");

    // Read raw body
    $body = file_get_contents('php://input');
    $bodyLen = strlen($body);

    if ($bodyLen < 9) {
        throw new Exception("Request body too short ({$bodyLen} bytes)");
    }

    // 1. Validate CRC32 Checksum
    $dataToChecksum = substr($body, 0, $bodyLen - 4);
    $receivedChecksumBytes = substr($body, $bodyLen - 4, 4);
    $receivedChecksum = unpack("N", $receivedChecksumBytes)[1];
    
    $calculatedChecksum = crc32($dataToChecksum);
    
    $receivedChecksumUnsigned = sprintf("%u", $receivedChecksum);
    $calculatedChecksumUnsigned = sprintf("%u", $calculatedChecksum);

    if ($receivedChecksumUnsigned !== $calculatedChecksumUnsigned) {
        writeLog("Checksum mismatch! Calc: {$calculatedChecksumUnsigned}, Recv: {$receivedChecksumUnsigned}", 'ERROR');
        header("HTTP/1.1 400 Bad Request");
        echo "Integrity check failed";
        exit;
    }

    // 2. Extract Mode
    $mode = ord($body[0]);
    $modeStr = ($mode === 0x01) ? 'FULL_USERINFO' : (($mode === 0x02) ? 'USERID_ONLY' : 'UNKNOWN');

    // 3. Decode AMF3 Payload
    $reader = new Amf3Reader($body, 1);
    $amfPayload = $reader->readValue();
    $afterAmfPos = $reader->getPos();

    // 4. Extract Raw Packet Bytes
    $rawLenBytes = substr($body, $afterAmfPos, 4);
    $rawLen = unpack("N", $rawLenBytes)[1];
    $rawPacketBytes = substr($body, $afterAmfPos + 4, $rawLen);

    // Sanity check body structure length
    if ($afterAmfPos + 8 + $rawLen !== $bodyLen) {
        throw new Exception("Body structure length mismatch. Expected: " . ($afterAmfPos + 8 + $rawLen) . " but got {$bodyLen}");
    }

    // 5. Log details for debugging
    writeLog("Successfully parsed packet. Mode: {$modeStr} ({$mode}), AMF Payload: " . json_encode($amfPayload) . ", Raw packet size: {$rawLen} bytes");

    // 6. Handle business cases based on msgId and payload
    $response = "";
    
    // Check if it's fire-and-forget (just log, no response needed)
    // You can also distinguish FnF using headers or by msgId ranges
    // Note: for fire-and-forget, the client on game server will close connection early,
    // so any response returned here won't block the game server but is ignored.
    
    switch ($msgId) {
        case 60001:
            // Case 1: Full mode test case
            $lUserId = isset($amfPayload['lUserId']) ? $amfPayload['lUserId'] : 0;
            $serverid = isset($amfPayload['serverid']) ? $amfPayload['serverid'] : 0;
            $userid = isset($amfPayload['userid']) ? $amfPayload['userid'] : '';
            
            writeLog("Business case 60001: user {$userid} (ID: {$lUserId}) on server {$serverid}");
            
            // Simulation of custom clear-text response
            $response = json_encode([
                "status" => "success",
                "message" => "Processed 60001 in FULL mode",
                "data" => [
                    "userId" => $lUserId,
                    "userName" => $userid,
                    "serverId" => $serverid,
                    "action" => "simulate_full_response"
                ]
            ]);
            break;

        case 60101:
            // Case 2: UserId only mode test case
            $lUserId = $amfPayload; // directly the integer User ID
            writeLog("Business case 60101: User ID {$lUserId}");

            $response = json_encode([
                "status" => "success",
                "message" => "Processed 60101 in USERID_ONLY mode",
                "data" => [
                    "userId" => $lUserId,
                    "action" => "simulate_userid_response"
                ]
            ]);
            break;

        case 60201:
            // Case 3: Fire and forget test case
            $lUserId = $amfPayload;
            writeLog("Business case 60201 (Fire-and-Forget): User ID {$lUserId}");
            // No response required, we just exit
            $response = "ACK";
            break;

        default:
            // Default handler
            writeLog("No specific business case for msgId: {$msgId}. Handling default.");
            $response = "DEFAULT_RESPONSE_FOR_MSGID_" . $msgId;
            break;
    }

    // Send the simulated clear-text response back to game server
    header("Content-Type: text/plain");
    echo $response;
    writeLog("Sent response: " . $response);

} catch (Exception $e) {
    writeLog("Error handling proxy request: " . $e->getMessage(), 'ERROR');
    header("HTTP/1.1 500 Internal Server Error");
    echo "Error: " . $e->getMessage();
}
