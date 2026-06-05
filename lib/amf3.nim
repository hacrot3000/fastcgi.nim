# mini_amf3.nim
import tables, strutils

type
  AmfKind* = enum
    akNull, akInt, akNumber, akBool, akString, akArray, akObject

  AmfValue* = ref object
    case kind*: AmfKind
    of akNull:
      discard
    of akInt:
      i*: int
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
proc amfInt*(v: int): AmfValue = AmfValue(kind: akInt, i: v)
proc amfNum*(v: SomeFloat): AmfValue = AmfValue(kind: akNumber, num: float64(v))
proc amfBool*(v: bool): AmfValue = AmfValue(kind: akBool, b: v)
proc amfStr*(v: string): AmfValue = AmfValue(kind: akString, s: v)
proc amfArray*(v: seq[AmfValue]): AmfValue = AmfValue(kind: akArray, arr: v)
proc amfObject*(v: OrderedTable[string, AmfValue]): AmfValue = AmfValue(kind: akObject, obj: v)

proc putU29(outp: var string, v: int) =
  let x = v and 0x1fffffff

  if x < 0x80:
    outp.add(char(x))
  elif x < 0x4000:
    outp.add(char(((x shr 7) and 0x7f) or 0x80))
    outp.add(char(x and 0x7f))
  elif x < 0x200000:
    outp.add(char(((x shr 14) and 0x7f) or 0x80))
    outp.add(char(((x shr 7) and 0x7f) or 0x80))
    outp.add(char(x and 0x7f))
  else:
    outp.add(char(((x shr 22) and 0x7f) or 0x80))
    outp.add(char(((x shr 15) and 0x7f) or 0x80))
    outp.add(char(((x shr 8) and 0x7f) or 0x80))
    outp.add(char(x and 0xff))

proc getU29(data: string, pos: var int): int =
  if pos >= data.len: raise newException(ValueError, "AMF3 EOF U29")

  var b = ord(data[pos])
  pos += 1

  if b < 128:
    return b

  result = (b and 0x7f) shl 7

  if pos >= data.len: raise newException(ValueError, "AMF3 EOF U29")
  b = ord(data[pos])
  pos += 1

  if b < 128:
    result = result or b
    return

  result = (result or (b and 0x7f)) shl 7

  if pos >= data.len: raise newException(ValueError, "AMF3 EOF U29")
  b = ord(data[pos])
  pos += 1

  if b < 128:
    result = result or b
    return

  result = (result or (b and 0x7f)) shl 8

  if pos >= data.len: raise newException(ValueError, "AMF3 EOF U29")
  b = ord(data[pos])
  pos += 1

  result = result or b

proc signExtend29(v: int): int =
  if (v and 0x10000000) != 0:
    result = v or not 0x1fffffff
  else:
    result = v

proc putFloat64BE(outp: var string, v: float64) =
  let bits = cast[uint64](v)
  for i in countdown(7, 0):
    outp.add(char((bits shr (i * 8)) and 0xff'u64))

proc getFloat64BE(data: string, pos: var int): float64 =
  if pos + 8 > data.len: raise newException(ValueError, "AMF3 EOF float64")

  var bits: uint64 = 0
  for i in 0 ..< 8:
    bits = (bits shl 8) or uint64(ord(data[pos + i]))

  pos += 8
  result = cast[float64](bits)

proc putUtf8Vr(outp: var string, s: string) =
  # AMF3 string inline marker: len << 1 | 1
  outp.putU29((s.len shl 1) or 1)
  outp.add(s)

proc getUtf8Vr(data: string, pos: var int): string =
  let header = getU29(data, pos)

  if (header and 1) == 0:
    raise newException(ValueError, "AMF3 string reference not supported")

  let n = header shr 1
  if pos + n > data.len:
    raise newException(ValueError, "AMF3 EOF string")

  result = data[pos ..< pos + n]
  pos += n

proc encodeAmf3*(v: AmfValue): string =
  case v.kind
  of akNull:
    result.add(char(0x01))

  of akBool:
    result.add(if v.b: char(0x03) else: char(0x02))

  of akInt:
    if v.i >= -268435456 and v.i <= 268435455:
      result.add(char(0x04))
      result.putU29(v.i and 0x1fffffff)
    else:
      result.add(char(0x05))
      result.putFloat64BE(float64(v.i))

  of akNumber:
    result.add(char(0x05))
    result.putFloat64BE(v.num)

  of akString:
    result.add(char(0x06))
    result.putUtf8Vr(v.s)

  of akArray:
    result.add(char(0x09))

    # Dense array, no associative keys.
    result.putU29((v.arr.len shl 1) or 1)

    # Empty associative section.
    result.putUtf8Vr("")

    for item in v.arr:
      result.add(encodeAmf3(item))

  of akObject:
    result.add(char(0x0A))

    # Anonymous dynamic object:
    # low bits:
    # 1 = inline object
    # 2 = inline traits
    # 8 = dynamic
    # sealed member count = 0
    #
    # trait header = 0b1011 = 11
    result.putU29(0x0B)

    # Empty class name.
    result.putUtf8Vr("")

    # Dynamic properties.
    for k, val in v.obj:
      result.putUtf8Vr(k)
      result.add(encodeAmf3(val))

    # End dynamic members.
    result.putUtf8Vr("")

proc decodeAmf3At(data: string, pos: var int): AmfValue =
  if pos >= data.len:
    raise newException(ValueError, "AMF3 EOF marker")

  let marker = ord(data[pos])
  pos += 1

  case marker
  of 0x00:
    result = amfNull() # undefined treated as null

  of 0x01:
    result = amfNull()

  of 0x02:
    result = amfBool(false)

  of 0x03:
    result = amfBool(true)

  of 0x04:
    result = amfInt(signExtend29(getU29(data, pos)))

  of 0x05:
    result = AmfValue(kind: akNumber, num: getFloat64BE(data, pos))

  of 0x06:
    result = amfStr(getUtf8Vr(data, pos))

  of 0x09:
    let header = getU29(data, pos)

    if (header and 1) == 0:
      raise newException(ValueError, "AMF3 array reference not supported")

    let denseCount = header shr 1

    var assoc = initOrderedTable[string, AmfValue]()

    while true:
      let key = getUtf8Vr(data, pos)
      if key.len == 0:
        break

      assoc[key] = decodeAmf3At(data, pos)

    var dense: seq[AmfValue] = @[]
    for i in 0 ..< denseCount:
      dense.add(decodeAmf3At(data, pos))

    if assoc.len == 0:
      result = amfArray(dense)
    else:
      for i, val in dense:
        assoc[$i] = val
      result = amfObject(assoc)

  of 0x0A:
    let header = getU29(data, pos)

    if (header and 1) == 0:
      raise newException(ValueError, "AMF3 object reference not supported")

    if (header and 2) == 0:
      raise newException(ValueError, "AMF3 trait reference not supported")

    let externalizable = (header and 4) != 0
    let dynamic = (header and 8) != 0
    let sealedCount = header shr 4

    if externalizable:
      raise newException(ValueError, "AMF3 externalizable object not supported")

    discard getUtf8Vr(data, pos) # class name

    var sealedNames: seq[string] = @[]
    for i in 0 ..< sealedCount:
      sealedNames.add(getUtf8Vr(data, pos))

    var obj = initOrderedTable[string, AmfValue]()

    for name in sealedNames:
      obj[name] = decodeAmf3At(data, pos)

    if dynamic:
      while true:
        let key = getUtf8Vr(data, pos)
        if key.len == 0:
          break

        obj[key] = decodeAmf3At(data, pos)

    result = amfObject(obj)

  else:
    raise newException(ValueError, "Unsupported AMF3 marker: 0x" & marker.toHex(2))

proc decodeAmf3*(data: string): AmfValue =
  var pos = 0
  result = decodeAmf3At(data, pos)

proc toHex*(s: string): string =
  for c in s:
    result.add(ord(c).toHex(2).toLowerAscii())

proc `$`*(v: AmfValue): string =
  case v.kind
  of akNull:
    "null"
  of akInt:
    $v.i
  of akNumber:
    $v.num
  of akBool:
    $v.b
  of akString:
    "\"" & v.s & "\""
  of akArray:
    var parts: seq[string] = @[]
    for x in v.arr:
      parts.add($x)
    "[" & parts.join(", ") & "]"
  of akObject:
    var parts: seq[string] = @[]
    for k, x in v.obj:
      parts.add(k & ": " & $x)
    "{" & parts.join(", ") & "}"
