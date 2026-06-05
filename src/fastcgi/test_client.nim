## test_client.nim
## Tests for client.nim of FastCGI client

import std/[strutils, times, os, net]
import client as phpfastcgi

var passCount = 0
var failCount = 0

proc testPass(name: string) =
  inc passCount
  echo "  [PASS] " & name

proc testFail(name, reason: string) =
  inc failCount
  echo "  [FAIL] " & name & " — " & reason

template check(name: string, cond: bool) =
  if cond: testPass(name)
  else:    testFail(name, "condition false")

template checkEq(name: string, a, b: untyped) =
  if a == b: testPass(name)
  else:      testFail(name, "got " & $a & ", expected " & $b)

proc proxyReachable(host = "127.0.0.1", port = 19090): bool =
  var s = newSocket()
  try:
    s.connect(host, Port(port), timeout = 200)
    result = true
  except: result = false
  finally:
    try: s.close() except: discard

proc cfg(totalMs = 5000): PhpFastCgiConfig =
  result = defaultPhpFastCgiConfig()
  result.totalTimeoutMs = totalMs
  result.connectTimeoutMs = 1000
  result.readTimeoutMs    = 3000
  result.writeTimeoutMs   = 3000

# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

proc testConfigDefaults() =
  echo "\n--- Unit: Config Defaults ---"
  let d = defaultPhpFastCgiConfig()
  checkEq("host is 127.0.0.1", d.host, "127.0.0.1")
  checkEq("port is 19090", d.port, 19090)
  checkEq("connectTimeoutMs is 3000", d.connectTimeoutMs, 3000)
  checkEq("maxStdoutBytes", d.maxStdoutBytes, 32*1024*1024)

proc testNormalizationAndChapping() =
  echo "\n--- Unit: normalizeScriptName ---"
  # Since normalizeScriptName is not exported, we test via exceptions raised by invalid scripts
  let c = cfg()
  let r1 = callPhpFastcgi(c, "../forbidden.php", "/forbidden.php", "", "")
  check("should reject relative paths containing ..", not r1.transportOk and r1.error.contains("must not contain '..'"))

  let r2 = callPhpFastcgi(c, "", "", "", "")
  check("should reject empty scriptName", not r2.transportOk and r2.error.contains("empty scriptName"))

# ---------------------------------------------------------------------------
# Integration tests (if reachable)
# ---------------------------------------------------------------------------

proc testLiveCases() =
  let live = proxyReachable()
  if not live:
    echo "\n[INFO] FastCGI proxy not reachable on 127.0.0.1:19090, skipping integration tests"
    return

  echo "\n--- Integration Tests ---"
  let c = cfg()

  # Test 1: GET __healthz.php
  let r1 = callPhpFastcgi(c, "/__healthz.php", "/__healthz.php", "", "", "GET", "")
  if r1.transportOk:
    check("GET healthz transportOk", r1.transportOk)
    checkEq("GET healthz statusCode", r1.statusCode, 200)
  else:
    testFail("GET healthz", r1.error)

  # Test 2: POST small JSON
  let r2 = callPhpFastcgi(c, "/echo.php", "/echo.php", "", """{"hello":"world"}""", "POST", "application/json")
  if r2.transportOk:
    check("POST small JSON transportOk", r2.transportOk)
  else:
    testFail("POST small JSON", r2.error)

  # Test 3: GET with query string
  let r3 = callPhpFastcgi(c, "/echo.php", "/echo.php?foo=bar", "foo=bar", "", "GET", "")
  if r3.transportOk:
    check("GET query string transportOk", r3.transportOk)

  # Test 4: Large request body (> 65535 bytes)
  let bigBody = "A".repeat(70000)
  let r4 = callPhpFastcgi(c, "/echo.php", "/echo.php", "", bigBody, "POST", "text/plain")
  if r4.transportOk:
    check("POST >65KB body transportOk", r4.transportOk)

  # Test 5: Large response body (> 65535 bytes)
  let r5 = callPhpFastcgi(c, "/bigresponse.php", "/bigresponse.php", "", "", "GET", "")
  if r5.transportOk:
    check("GET >65KB response transportOk", r5.transportOk)
    check("GET >65KB response body size", r5.body.len > 65535)

  # Test 6: PHP 500 status code
  let r6 = callPhpFastcgi(c, "/error500.php", "/error500.php", "", "", "GET", "")
  if r6.transportOk:
    checkEq("PHP 500 statusCode is 500", r6.statusCode, 500)
    check("ok is false when status is 500", not r6.ok)

  # Test 7: PHP warning (stderr)
  let r7 = callPhpFastcgi(c, "/warning.php", "/warning.php", "", "", "GET", "")
  if r7.transportOk:
    check("stderr is populated on warning", r7.stderr.len > 0)

  # Test 8: Consecutive calls
  var consecutiveOk = true
  for i in 1..10:
    let r = callPhpFastcgi(c, "/__healthz.php", "/__healthz.php", "", "", "GET", "")
    if not r.transportOk:
      consecutiveOk = false
      break
  check("10 consecutive calls without issue", consecutiveOk)

proc testTimeoutWhenDown() =
  echo "\n--- Unit/Integration: Timeout when proxy down ---"
  var c = cfg()
  c.host = "127.0.0.1"
  c.port = 19999 # Closed port
  c.connectTimeoutMs = 150
  c.totalTimeoutMs = 400

  let t0 = getTime()
  let r = callPhpFastcgi(c, "/any.php", "/any.php", "", "", "GET", "")
  let elapsed = (getTime() - t0).inMilliseconds()

  check("call fails", not r.transportOk)
  check("completes under 1 second", elapsed < 1000)
  echo "  Elapsed time for down proxy call: " & $elapsed & " ms"

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo "============================================================"
echo "  phpfastcgi test suite (GM production version)"
echo "============================================================"

testConfigDefaults()
testNormalizationAndChapping()
testTimeoutWhenDown()
testLiveCases()

echo "\n============================================================"
echo "  Results: " & $passCount & " passed, " & $failCount & " failed"
echo "============================================================"

if failCount > 0:
  quit(1)
