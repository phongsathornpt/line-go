package thrift

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

const (
	tmcMaxVarintBytes = 10
	tmcStringTableID  = 16
	tmcStringTableRef = 17
)

// UnmarshalTMoreCompactStruct decodes LINE's TMoreCompact push response
// payload into the ordinary Thrift value model.
func UnmarshalTMoreCompactStruct(data []byte) (StructValue, error) {
	return UnmarshalTMoreCompactStructWithLimits(data, DecodeLimits{})
}

// UnmarshalTMoreCompactStructWithLimits decodes a push response under caller
// supplied recursion, item, and binary-size limits.
func UnmarshalTMoreCompactStructWithLimits(data []byte, limits DecodeLimits) (StructValue, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("thrift tmc: response is %d bytes; need at least 4", len(data))
	}
	d := tmcDecoder{
		data:   data,
		limits: limits,
		tree:   make([]int, 512),
	}
	d.pos = 3
	if err := d.readTypeHeader(); err != nil {
		return nil, fmt.Errorf("thrift tmc: read type header: %w", err)
	}
	if err := d.readStringTable(); err != nil {
		return nil, fmt.Errorf("thrift tmc: read string table: %w", err)
	}
	bitmap, err := d.readUvarint()
	if err != nil {
		return nil, fmt.Errorf("thrift tmc: read result bitmap: %w", err)
	}
	result, err := d.readStruct(bitmap, 0)
	if err != nil {
		return nil, fmt.Errorf("thrift tmc: decode result struct: %w", err)
	}
	return result, nil
}

type tmcDecoder struct {
	data         []byte
	pos          int
	limits       DecodeLimits
	items        int
	binaryBytes  int
	tree         []int
	types        []Type
	typePos      int
	stringTable  []string
	lastStringID int64
}

func (d *tmcDecoder) readTypeHeader() error {
	if err := d.buildTypeTree(); err != nil {
		return err
	}
	length, err := d.readUvarint()
	if err != nil {
		return err
	}
	if length > uint64(d.limits.MaxBinaryBytes) || length > uint64(len(d.data)-d.pos) {
		return fmt.Errorf("compressed type header length %d exceeds available data or limit", length)
	}
	if int(length) > d.limits.MaxItems {
		return fmt.Errorf("compressed type header length %d exceeds item limit %d", length, d.limits.MaxItems)
	}
	header := d.data[d.pos : d.pos+int(length)]
	d.pos += int(length)
	d.types = make([]Type, 0, len(header)*2)
	node := 0
	for _, value := range header {
		for bit := 7; bit >= 0; bit-- {
			if value&(1<<uint(bit)) == 0 {
				node = node*2 + 1
			} else {
				node = node*2 + 2
			}
			if node >= len(d.tree) {
				return fmt.Errorf("invalid Huffman node %d", node)
			}
			if d.tree[node] != 0 {
				d.types = append(d.types, Type(d.tree[node]))
				node = 0
			}
		}
	}
	return nil
}

func (d *tmcDecoder) buildTypeTree() error {
	patterns := []struct {
		bits   string
		typeID Type
	}{
		{"1011", TypeBool},
		{"10101001", TypeByte},
		{"10101000", TypeDouble},
		{"1010111", TypeI16},
		{"01", TypeI32},
		{"00", TypeI64},
		{"10100", TypeString},
		{"1101", TypeStruct},
		{"1010110", TypeMap},
		{"1010101", TypeSet},
		{"1100", TypeList},
		{"111", tmcStringTableID},
		{"100", tmcStringTableRef},
	}
	for _, pattern := range patterns {
		node := 0
		for _, bit := range pattern.bits {
			switch bit {
			case '0':
				node = node*2 + 1
			case '1':
				node = node*2 + 2
			}
			if node >= len(d.tree) {
				return fmt.Errorf("type code %q exceeds Huffman tree", pattern.bits)
			}
		}
		if d.tree[node] != 0 {
			return fmt.Errorf("duplicate Huffman code %q", pattern.bits)
		}
		d.tree[node] = int(pattern.typeID)
	}
	return nil
}

func (d *tmcDecoder) readStringTable() error {
	count, err := d.readUvarint()
	if err != nil {
		return err
	}
	if count > uint64(d.limits.MaxItems) || count > uint64((len(d.data)-d.pos)/17) {
		return fmt.Errorf("string table count %d exceeds available data or item limit", count)
	}
	d.stringTable = make([]string, 0, int(count))
	for range int(count) {
		entry := d.data[d.pos : d.pos+17]
		d.pos += 17
		text := make([]byte, 1+32)
		text[0] = entry[0]
		const hex = "0123456789abcdef"
		for index, value := range entry[1:] {
			text[1+index*2] = hex[value>>4]
			text[2+index*2] = hex[value&0x0f]
		}
		d.stringTable = append(d.stringTable, string(text))
	}
	return nil
}

func (d *tmcDecoder) readStruct(bitmap uint64, depth int) (StructValue, error) {
	if depth > d.limits.MaxDepth {
		return nil, fmt.Errorf("nesting depth exceeds limit %d", d.limits.MaxDepth)
	}
	fields := make(StructValue, 0)
	for fieldID := 0; bitmap != 0; fieldID++ {
		if bitmap&1 != 0 {
			if fieldID > math.MaxInt16 {
				return nil, fmt.Errorf("field ID %d exceeds i16", fieldID)
			}
			if err := d.addItems(1); err != nil {
				return nil, err
			}
			fieldType, err := d.nextType()
			if err != nil {
				return nil, err
			}
			value, err := d.readValue(fieldType, depth+1)
			if err != nil {
				return nil, fmt.Errorf("field %d: %w", fieldID, err)
			}
			fields = append(fields, Field{ID: int16(fieldID), Value: value})
		}
		bitmap >>= 1
	}
	return fields, nil
}

func (d *tmcDecoder) readValue(typeID Type, depth int) (Value, error) {
	if depth > d.limits.MaxDepth {
		return nil, fmt.Errorf("nesting depth exceeds limit %d", d.limits.MaxDepth)
	}
	switch typeID {
	case TypeBool:
		value, err := d.readUvarint()
		return BoolValue(value != 0), err
	case TypeByte:
		value, err := d.readByte()
		return ByteValue(int8(value)), err
	case TypeI16:
		value, err := d.readZigzag()
		if err != nil {
			return nil, err
		}
		if value < math.MinInt16 || value > math.MaxInt16 {
			return nil, fmt.Errorf("integer %d overflows i16", value)
		}
		return I16Value(value), nil
	case TypeI32:
		value, err := d.readZigzag()
		if err != nil {
			return nil, err
		}
		if value < math.MinInt32 || value > math.MaxInt32 {
			return nil, fmt.Errorf("integer %d overflows i32", value)
		}
		return I32Value(value), nil
	case TypeI64:
		value, err := d.readZigzag()
		return I64Value(value), err
	case TypeDouble:
		value, err := d.readFixed(8)
		if err != nil {
			return nil, err
		}
		return DoubleValue(math.Float64frombits(binary.LittleEndian.Uint64(value))), nil
	case TypeString:
		value, err := d.readString()
		if err != nil {
			return nil, err
		}
		if utf8.ValidString(value) {
			return StringValue(value), nil
		}
		return BinaryValue([]byte(value)), nil
	case TypeStruct:
		bitmap, err := d.readUvarint()
		if err != nil {
			return nil, err
		}
		return d.readStruct(bitmap, depth+1)
	case TypeMap:
		return d.readMap(depth + 1)
	case TypeSet, TypeList:
		return d.readSequence(typeID, depth+1)
	case tmcStringTableID:
		delta, err := d.readZigzag()
		if err != nil {
			return nil, err
		}
		if delta > 0 && d.lastStringID > math.MaxInt64-delta || delta < 0 && d.lastStringID < math.MinInt64-delta {
			return nil, fmt.Errorf("string ID delta overflows i64")
		}
		d.lastStringID += delta
		return StringValue(fmt.Sprintf("%d", d.lastStringID)), nil
	case tmcStringTableRef:
		index, err := d.readUvarint()
		if err != nil {
			return nil, err
		}
		if index >= uint64(len(d.stringTable)) {
			return nil, fmt.Errorf("string table index %d is out of range", index)
		}
		return StringValue(d.stringTable[index]), nil
	default:
		return nil, fmt.Errorf("unsupported compressed type %d", typeID)
	}
}

func (d *tmcDecoder) readMap(depth int) (Value, error) {
	if depth > d.limits.MaxDepth {
		return nil, fmt.Errorf("nesting depth exceeds limit %d", d.limits.MaxDepth)
	}
	count, err := d.readUvarint()
	if err != nil {
		return nil, err
	}
	if count > uint64(d.limits.MaxItems) {
		return nil, fmt.Errorf("map entry count %d exceeds item limit %d", count, d.limits.MaxItems)
	}
	result := MapValue{Entries: make([]MapEntry, 0, int(count))}
	if count == 0 {
		return result, nil
	}
	types, err := d.readByte()
	if err != nil {
		return nil, err
	}
	result.KeyType, err = tmcCompactType(types >> 4)
	if err != nil {
		return nil, err
	}
	result.ValueType, err = tmcCompactType(types & 0x0f)
	if err != nil {
		return nil, err
	}
	if err := d.addItems(int(count) * 2); err != nil {
		return nil, err
	}
	for range int(count) {
		key, err := d.readValue(result.KeyType, depth+1)
		if err != nil {
			return nil, fmt.Errorf("map key: %w", err)
		}
		value, err := d.readValue(result.ValueType, depth+1)
		if err != nil {
			return nil, fmt.Errorf("map value: %w", err)
		}
		result.Entries = append(result.Entries, MapEntry{Key: key, Value: value})
	}
	return result, nil
}

func (d *tmcDecoder) readSequence(typeID Type, depth int) (Value, error) {
	if depth > d.limits.MaxDepth {
		return nil, fmt.Errorf("nesting depth exceeds limit %d", d.limits.MaxDepth)
	}
	sizeType, err := d.readByte()
	if err != nil {
		return nil, err
	}
	count := uint64(sizeType >> 4)
	elementType, err := tmcCompactType(sizeType & 0x0f)
	if err != nil {
		return nil, err
	}
	if count == 15 {
		count, err = d.readUvarint()
		if err != nil {
			return nil, err
		}
	}
	if count > uint64(d.limits.MaxItems) {
		return nil, fmt.Errorf("sequence count %d exceeds item limit %d", count, d.limits.MaxItems)
	}
	if err := d.addItems(int(count)); err != nil {
		return nil, err
	}
	values := make([]Value, 0, int(count))
	for range int(count) {
		value, err := d.readValue(elementType, depth+1)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if typeID == TypeSet {
		return SetValue{ElementType: elementType, Values: values}, nil
	}
	return ListValue{ElementType: elementType, Values: values}, nil
}

func (d *tmcDecoder) nextType() (Type, error) {
	if d.typePos >= len(d.types) {
		return 0, fmt.Errorf("compressed type sequence ended at item %d", d.typePos)
	}
	typeID := d.types[d.typePos]
	d.typePos++
	return typeID, nil
}

func (d *tmcDecoder) readString() (string, error) {
	length, err := d.readUvarint()
	if err != nil {
		return "", err
	}
	if length > uint64(d.limits.MaxBinaryBytes-d.binaryBytes) || length > uint64(len(d.data)-d.pos) {
		return "", fmt.Errorf("string length %d exceeds available data or binary limit", length)
	}
	value := d.data[d.pos : d.pos+int(length)]
	d.pos += int(length)
	d.binaryBytes += int(length)
	return string(value), nil
}

func (d *tmcDecoder) readZigzag() (int64, error) {
	encoded, err := d.readUvarint()
	if err != nil {
		return 0, err
	}
	return int64(encoded>>1) ^ -int64(encoded&1), nil
}

func (d *tmcDecoder) readUvarint() (uint64, error) {
	var value uint64
	for index := 0; index < tmcMaxVarintBytes; index++ {
		byteValue, err := d.readByte()
		if err != nil {
			return 0, err
		}
		if index == 9 && byteValue > 1 {
			return 0, fmt.Errorf("varint overflows u64")
		}
		value |= uint64(byteValue&0x7f) << (7 * index)
		if byteValue&0x80 == 0 {
			return value, nil
		}
	}
	return 0, fmt.Errorf("varint exceeds %d bytes", tmcMaxVarintBytes)
}

func (d *tmcDecoder) readByte() (byte, error) {
	if d.pos >= len(d.data) {
		return 0, fmt.Errorf("unexpected end of input at byte %d", d.pos)
	}
	value := d.data[d.pos]
	d.pos++
	return value, nil
}

func (d *tmcDecoder) readFixed(size int) ([]byte, error) {
	if size < 0 || size > len(d.data)-d.pos {
		return nil, fmt.Errorf("need %d bytes at offset %d; have %d", size, d.pos, len(d.data)-d.pos)
	}
	value := d.data[d.pos : d.pos+size]
	d.pos += size
	return value, nil
}

func (d *tmcDecoder) addItems(count int) error {
	if count < 0 || count > d.limits.MaxItems-d.items {
		return fmt.Errorf("decoded item count exceeds limit %d", d.limits.MaxItems)
	}
	d.items += count
	return nil
}

func tmcCompactType(typeID byte) (Type, error) {
	switch typeID {
	case 0:
		return TypeStop, nil
	case 1, 2:
		return TypeBool, nil
	case 3:
		return TypeByte, nil
	case 4:
		return TypeI16, nil
	case 5:
		return TypeI32, nil
	case 6:
		return TypeI64, nil
	case 7:
		return TypeDouble, nil
	case 8:
		return TypeString, nil
	case 9:
		return TypeList, nil
	case 10:
		return TypeSet, nil
	case 11:
		return TypeMap, nil
	case 12:
		return TypeStruct, nil
	default:
		return 0, fmt.Errorf("invalid compact element type %d", typeID)
	}
}
