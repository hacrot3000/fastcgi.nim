# mini_amf0.nim
# AMF0 minimal encoder/decoder for:
# number(int/float), bool, string, array, object, null

import tables, strutils, algorithm

type
  AmfKind* = enum
    akNull, akNumber, akBool, akString, akArray, akObject

  AmfValue* = ref object
    case kind*: AmfKind
    of akNull:
      discard
    of akNumber:
      num*: float64
    of akBool:
      b*: bool
    of akString:
      s*: string
    of akArray:
      arr*: seq[AmfValue]
    of akObject:
      obj*: OrderedTable[string, AmfValue]

proc amfNull*(): AmfValue = AmfValue(kind: akNull)
proc amfNum*(v: SomeNumber): AmfValue = AmfValue(kind: akNumber, num: float64(v))
proc amfBool*(v: bool): AmfValue = AmfValue(kind: akBool, b: v)
proc amfStr*(v: string): AmfValue = AmfValue(kind: akString, s: v)
proc amfArray*(v: seq[AmfValue]): AmfValue = AmfValue(kind: akArray, arr: v)
proc amfObject*(v: OrderedTable[string, AmfValue]): AmfValue = AmfValue(kind: akObject, obj: v)

proc putU16BE(outp: var string, v: int) =
  outp.add(char((v shr 8) and 0xff))
  outp.add(char(v and 0xff))

proc putU32BE(outp: var string, v: int) =
  outp.add(char((v shr 24) and 0xff))
  outp.add(char((v shr 16) and 0xff))
  outp.add(char((v shr 8) and 0xff))
  outp.add(char(v and 0xff))

proc getU16BE(data: string, pos: var int): int =
  if pos + 2 > data.len: raise newException(ValueError, "AMF0 EOF u16")
  result = (ord(data[pos]) shl 8) or ord(data[pos + 1])
  pos += 2

proc getU32BE(data: string, pos: var int): int =
  if pos + 4 > data.len: raise newException(ValueError, "AMF0 EOF u32")
  result =
    (ord(data[pos]) shl 24) or
    (ord(data[pos + 1]) shl 16) or
    (ord(data[pos + 2]) shl 8) or
    ord(data[pos + 3])
  pos += 4

proc putFloat64BE(outp: var string, v: float64) =
  var bits = cast[uint64](v)
  for i in countdown(7, 0):
    outp.add(char((bits shr (i * 8)) and 0xff'u64))

proc getFloat64BE(data: string, pos: var int): float64 =
  if pos + 8 > data.len: raise newException(ValueError, "AMF0 EOF float64")
  var bits: uint64 = 0
  for i in 0 ..< 8:
    bits = (bits shl 8) or uint64(ord(data[pos + i]))
  pos += 8
  result = cast[float64](bits)

proc encodeAmf0*(v: AmfValue): string =
  case v.kind
  of akNull:
    result.add(char(0x05))

  of akNumber:
    result.add(char(0x00))
    result.putFloat64BE(v.num)

  of akBool:
    result.add(char(0x01))
    result.add(if v.b: char(1) else: char(0))

  of akString:
    if v.s.len > 65535:
      raise newException(ValueError, "AMF0 short string max 65535 bytes")
    result.add(char(0x02))
    result.putU16BE(v.s.len)
    result.add(v.s)

  of akObject:
    result.add(char(0x03))
    for k, val in v.obj:
      if k.len > 65535:
        raise newException(ValueError, "AMF0 object key max 65535 bytes")
      result.putU16BE(k.len)
      result.add(k)
      result.add(encodeAmf0(val))
    # object end marker: 00 00 09
    result.add(char(0x00))
    result.add(char(0x00))
    result.add(char(0x09))

  of akArray:
    # ECMA array marker, compatible with many AMF0 clients
    result.add(char(0x08))
    result.putU32BE(v.arr.len)
    for i, val in v.arr:
      let k = $i
      result.putU16BE(k.len)
      result.add(k)
      result.add(encodeAmf0(val))
    result.add(char(0x00))
    result.add(char(0x00))
    result.add(char(0x09))

proc decodeAmf0At(data: string, pos: var int): AmfValue =
  if pos >= data.len: raise newException(ValueError, "AMF0 EOF marker")

  let marker = ord(data[pos])
  pos += 1

  case marker
  of 0x00:
    result = amfNum(getFloat64BE(data, pos))

  of 0x01:
    if pos >= data.len: raise newException(ValueError, "AMF0 EOF bool")
    result = amfBool(ord(data[pos]) != 0)
    pos += 1

  of 0x02:
    let n = getU16BE(data, pos)
    if pos + n > data.len: raise newException(ValueError, "AMF0 EOF string")
    result = amfStr(data[pos ..< pos + n])
    pos += n

  of 0x03:
    var t = initOrderedTable[string, AmfValue]()
    while true:
      if pos + 3 <= data.len and
         ord(data[pos]) == 0 and
         ord(data[pos + 1]) == 0 and
         ord(data[pos + 2]) == 0x09:
        pos += 3
        break

      let keyLen = getU16BE(data, pos)
      if pos + keyLen > data.len: raise newException(ValueError, "AMF0 EOF object key")
      let key = data[pos ..< pos + keyLen]
      pos += keyLen

      t[key] = decodeAmf0At(data, pos)

    result = amfObject(t)

  of 0x05, 0x06:
    result = amfNull()

  of 0x08:
    discard getU32BE(data, pos) # associative count, often unreliable
    var pairs = initOrderedTable[string, AmfValue]()
    var numericItems: seq[(int, AmfValue)] = @[]

    while true:
      if pos + 3 <= data.len and
         ord(data[pos]) == 0 and
         ord(data[pos + 1]) == 0 and
         ord(data[pos + 2]) == 0x09:
        pos += 3
        break

      let keyLen = getU16BE(data, pos)
      if pos + keyLen > data.len: raise newException(ValueError, "AMF0 EOF array key")
      let key = data[pos ..< pos + keyLen]
      pos += keyLen

      let val = decodeAmf0At(data, pos)
      try:
        numericItems.add((parseInt(key), val))
      except ValueError:
        pairs[key] = val

    if pairs.len == 0:
      numericItems.sort(proc(a, b: (int, AmfValue)): int = cmp(a[0], b[0]))
      var arr: seq[AmfValue] = @[]
      for item in numericItems:
        arr.add(item[1])
      result = amfArray(arr)
    else:
      for item in numericItems:
        pairs[$item[0]] = item[1]
      result = amfObject(pairs)

  else:
    raise newException(ValueError, "Unsupported AMF0 marker: 0x" & marker.toHex(2))

proc decodeAmf0*(data: string): AmfValue =
  var pos = 0
  result = decodeAmf0At(data, pos)

proc toHex*(s: string): string =
  for c in s:
    result.add(ord(c).toHex(2).toLowerAscii())

proc `$`*(v: AmfValue): string =
  case v.kind
  of akNull: "null"
  of akNumber: $v.num
  of akBool: $v.b
  of akString: "\"" & v.s & "\""
  of akArray:
    var parts: seq[string] = @[]
    for x in v.arr: parts.add($x)
    "[" & parts.join(", ") & "]"
  of akObject:
    var parts: seq[string] = @[]
    for k, x in v.obj: parts.add(k & ": " & $x)
    "{" & parts.join(", ") & "}"
