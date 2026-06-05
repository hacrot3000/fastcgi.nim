import std/[strutils, rdstdin, httpclient, tables]
import "./fastcgi.nim/lib/amf0" as amf0
import "./fastcgi.nim/lib/amf3" as amf3

proc prompt(label: string, default: string): string =
  var val = ""
  try:
    val = readLineFromStdin(label & " [" & default & "]: ").strip()
  except EOFError:
    quit(0)
  if val == "":
    return default
  return val

proc formatHex(s: string): string =
  result = ""
  for i, c in s:
    if i > 0 and i mod 16 == 0:
      result.add("\n")
    elif i > 0 and i mod 2 == 0:
      result.add(" ")
    result.add(ord(c).toHex(2).toLowerAscii())

proc buildAmf0Object(): amf0.AmfValue =
  var t = initOrderedTable[string, amf0.AmfValue]()
  t["number"] = amf0.amfNum(42.5)
  t["string"] = amf0.amfStr("Hello from AMF0 client")
  t["bool"] = amf0.amfBool(true)
  t["null"] = amf0.amfNull()
  
  var arr = newSeq[amf0.AmfValue]()
  arr.add(amf0.amfNum(1))
  arr.add(amf0.amfStr("two"))
  t["array"] = amf0.amfArray(arr)
  
  return amf0.amfObject(t)

proc buildAmf3Object(): amf3.AmfValue =
  var t = initOrderedTable[string, amf3.AmfValue]()
  t["number"] = amf3.amfNum(88.88)
  t["int"] = amf3.amfInt(2026)
  t["string"] = amf3.amfStr("Hello from AMF3 client")
  t["bool"] = amf3.amfBool(false)
  t["null"] = amf3.amfNull()
  
  var arr = newSeq[amf3.AmfValue]()
  arr.add(amf3.amfInt(10))
  arr.add(amf3.amfStr("nested-string"))
  t["array"] = amf3.amfArray(arr)
  
  return amf3.amfObject(t)

proc runTest() =
  echo "=== Naruto AMF Gateway Test Client ==="
  let host = prompt("Host", "127.0.0.1")
  let portStr = prompt("gm-proxy Port", "19090")
  let port = try: parseInt(portStr) except ValueError: 19090
  let scriptName = prompt("PHP Script", "amftest.php")
  let amfVersionStr = prompt("AMF Version (0 or 3)", "3")
  let amfVersion = try: parseInt(amfVersionStr) except ValueError: 3

  if amfVersion != 0 and amfVersion != 3:
    echo "[ERROR] Invalid AMF version: ", amfVersionStr
    return

  let cleanScript = scriptName.strip(chars = {'/'})
  let url = "http://" & host & ":" & $port & "/" & cleanScript & "?version=" & $amfVersion
  echo "Target URL: " & url

  var postBody = ""
  if amfVersion == 0:
    let clientVal = buildAmf0Object()
    echo "\n--- Constructed AMF0 Object ---"
    echo $clientVal
    
    postBody = amf0.encodeAmf0(clientVal)
  else:
    let clientVal = buildAmf3Object()
    echo "\n--- Constructed AMF3 Object ---"
    echo $clientVal
    
    # PHP's amf_decode starts with AMF0 deserialization.
    # To transition to AMF3, we prefix the payload with AMF0_AMF3 marker (0x11 = 17)
    let encodedAmf3 = amf3.encodeAmf3(clientVal)
    postBody = char(0x11) & encodedAmf3

  echo "\n--- Request Binary Payload (Hex) ---"
  echo formatHex(postBody)
  echo "\nSending HTTP POST request..."

  try:
    let client = newHttpClient(timeout = 5000)
    client.headers = newHttpHeaders({"Content-Type": "application/x-amf"})
    let response = client.post(url, postBody)
    
    echo "\n=== RESPONSE ==="
    echo "HTTP Status: ", response.status
    
    if response.code == Http200:
      let respBody = response.body
      echo "Response Length: ", respBody.len, " bytes"
      echo "\n--- Response Binary Payload (Hex) ---"
      echo formatHex(respBody)
      
      if respBody.len == 0:
        echo "[WARNING] Received empty response from server."
        return

      if amfVersion == 0:
        try:
          let decoded = amf0.decodeAmf0(respBody)
          echo "\n--- Decoded AMF0 Response ---"
          echo $decoded
        except Exception as e:
          echo "\n[ERROR] Failed to decode AMF0 response: ", e.msg
      else:
        # Decode AMF3. Check if prefixed with AMF0_AMF3 (0x11)
        var actualPayload = respBody
        if ord(respBody[0]) == 0x11:
          actualPayload = respBody[1 .. ^1]
        else:
          echo "[NOTE] Response was not prefixed with AMF0_AMF3 (0x11)"
          
        try:
          let decoded = amf3.decodeAmf3(actualPayload)
          echo "\n--- Decoded AMF3 Response ---"
          echo $decoded
        except Exception as e:
          echo "\n[ERROR] Failed to decode AMF3 response: ", e.msg
          # Attempt to dump as AMF0 just in case
          try:
            echo "Attempting fallback AMF0 decode..."
            let decoded = amf0.decodeAmf0(respBody)
            echo "Fallback Decoded AMF0: ", $decoded
          except Exception:
            discard
    else:
      echo "\n[ERROR] Server returned non-200 status: ", response.status
      echo "Response body:"
      echo response.body
  except Exception as e:
    echo "\n=== ERROR ==="
    echo "Failed to send request: ", e.msg

if isMainModule:
  runTest()
