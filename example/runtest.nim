import std/[strutils, rdstdin, httpclient]

proc prompt(label: string, default: string): string =
  var val = ""
  try:
    val = readLineFromStdin(label & " [" & default & "]: ").strip()
  except EOFError:
    quit(0)
  if val == "":
    return default
  return val

proc runHttpTest(host: string, port: int, scriptName, meth, queryString, body: string, saveFile: string) =
  echo "\n--- Running HTTP Protocol Test (for gm-proxy) ---"
  let cleanScript = scriptName.strip(chars = {'/'})
  let url = "http://" & host & ":" & $port & "/" & cleanScript & (if queryString != "": "?" & queryString else: "")
  echo "Target URL: " & url
  
  try:
    let client = newHttpClient(timeout = 5000)
    let response = if meth == "POST":
                     client.post(url, body)
                   else:
                     client.get(url)
    
    echo "\n=== RESPONSE ==="
    echo "HTTP Status: ", response.status
    echo "\n--- Headers ---"
    for k, v in response.headers:
      echo k & ": " & v
      
    if saveFile != "":
      try:
        writeFile(saveFile, response.body)
        echo "\n[INFO] Response body successfully saved to: " & saveFile
      except Exception as e:
        echo "\n[ERROR] Failed to write response to file: " & e.msg
    else:
      echo "\n--- Body ---"
      echo response.body
  except Exception as e:
    echo "\n=== ERROR ==="
    echo "Failed to send HTTP request: ", e.msg

proc main() =
  echo "=== Naruto PHP Gateway Test Client ==="
  
  let host = prompt("Host", "127.0.0.1")
  
  let portStr = prompt("gm-proxy Port", "19090")
  let port = try: parseInt(portStr) except ValueError: 19090
  
  let scriptName = prompt("PHP Script to run", "index.php")
  let methodUpper = prompt("HTTP Method (GET/POST)", "GET").toUpperAscii()
  let queryString = prompt("GET Query String (optional)", "")
  let body = prompt("POST Body (optional)", "")
    
  let saveToFile = prompt("Save response body to a file? (y/n)", "n").toLowerAscii()
  var savePath = ""
  if saveToFile == "y" or saveToFile == "yes":
    savePath = prompt("Enter filename to save", "response.html")
    
  runHttpTest(host, port, scriptName, methodUpper, queryString, body, savePath)

if isMainModule:
  main()
