package thrift

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// Type is a Thrift field type.
type Type byte

// Thrift type identifiers used in field descriptors.
const (
	TypeStop   Type = 0
	TypeVoid   Type = 1
	TypeBool   Type = 2
	TypeByte   Type = 3
	TypeDouble Type = 4
	TypeI16    Type = 6
	TypeI32    Type = 8
	TypeI64    Type = 10
	TypeString Type = 11
	TypeStruct Type = 12
	TypeMap    Type = 13
	TypeSet    Type = 14
	TypeList   Type = 15
)

const (
	compactBoolTrue  byte = 1
	compactBoolFalse byte = 2
	compactByte      byte = 3
	compactI16       byte = 4
	compactI32       byte = 5
	compactI64       byte = 6
	compactDouble    byte = 7
	compactBinary    byte = 8
	compactList      byte = 9
	compactSet       byte = 10
	compactMap       byte = 11
	compactStruct    byte = 12
	compactStop      byte = 0

	maxEncodeDepth      = 64
	maxEncodeCollection = 1 << 20
	defaultDecodeDepth  = 64
	defaultDecodeItems  = 1 << 20
	defaultDecodeBinary = 64 << 20
)

// Value is a value accepted by the Compact Protocol codec. Its implementations
// are the scalar and container types declared in this package.
type Value interface {
	thriftType() Type
}

// BoolValue is a Thrift bool.
type BoolValue bool

func (BoolValue) thriftType() Type { return TypeBool }

// ByteValue is a Thrift byte.
type ByteValue int8

func (ByteValue) thriftType() Type { return TypeByte }

// I16Value is a Thrift i16.
type I16Value int16

func (I16Value) thriftType() Type { return TypeI16 }

// I32Value is a Thrift i32, commonly used for enums.
type I32Value int32

func (I32Value) thriftType() Type { return TypeI32 }

// I64Value is a Thrift i64.
type I64Value int64

func (I64Value) thriftType() Type { return TypeI64 }

// DoubleValue is a Thrift double.
type DoubleValue float64

func (DoubleValue) thriftType() Type { return TypeDouble }

// StringValue is a UTF-8 Thrift string.
type StringValue string

func (StringValue) thriftType() Type { return TypeString }

// BinaryValue is a Thrift binary value. Decoding returns this type for Thrift
// STRING fields because the wire format does not distinguish string from binary.
type BinaryValue []byte

func (BinaryValue) thriftType() Type { return TypeString }

// Field is a field in a Thrift struct. Fields are encoded in slice order.
type Field struct {
	ID    int16
	Value Value
}

// StructValue is an ordered Thrift struct.
type StructValue []Field

func (StructValue) thriftType() Type { return TypeStruct }

// ListValue is a homogeneous Thrift list.
type ListValue struct {
	ElementType Type
	Values      []Value
}

func (ListValue) thriftType() Type { return TypeList }

// SetValue is a homogeneous Thrift set.
type SetValue struct {
	ElementType Type
	Values      []Value
}

func (SetValue) thriftType() Type { return TypeSet }

// MapEntry is one key/value pair in a Thrift map.
type MapEntry struct {
	Key   Value
	Value Value
}

// MapValue is a homogeneous Thrift map. Entry order is preserved on the wire.
type MapValue struct {
	KeyType   Type
	ValueType Type
	Entries   []MapEntry
}

func (MapValue) thriftType() Type { return TypeMap }

// DecodeLimits bounds aggregate resource use while decoding untrusted protocol
// data. MaxItems counts struct fields, sequence elements, and map keys and values.
// MaxBinaryBytes counts copied binary payload bytes. Zero selects the package
// default; negative limits are rejected.
type DecodeLimits struct {
	MaxDepth       int
	MaxItems       int
	MaxBinaryBytes int
}

// MarshalCompactStruct encodes one Thrift struct without a message envelope.
func MarshalCompactStruct(value StructValue) ([]byte, error) {
	w := compactWriter{}
	if err := w.writeStruct(value, 0); err != nil {
		return nil, err
	}
	return w.data, nil
}

// MarshalCompactRequest encodes the custom LINE v4 request header, a compact
// args struct, and LINEJS's trailing zero byte.
func MarshalCompactRequest(method string, args StructValue) ([]byte, error) {
	name := []byte(method)
	if !utf8.Valid(name) {
		return nil, fmt.Errorf("thrift compact: method name is not valid UTF-8")
	}
	if len(name) > math.MaxUint8 {
		return nil, fmt.Errorf("thrift compact: method name is %d bytes; maximum is 255", len(name))
	}

	request := make([]byte, 0, 4+len(name)+len(args)*5+1)
	request = append(request, 0x82, 0x21, 0x00, byte(len(name)))
	request = append(request, name...)
	if len(args) != 0 {
		body, err := MarshalCompactStruct(args)
		if err != nil {
			return nil, err
		}
		request = append(request, body...)
	}
	request = append(request, 0x00)
	return request, nil
}

// UnmarshalCompactStruct decodes exactly one Thrift struct without a message
// envelope, rejecting trailing bytes and inputs that exceed default limits.
func UnmarshalCompactStruct(data []byte) (StructValue, error) {
	return UnmarshalCompactStructWithLimits(data, DecodeLimits{})
}

// UnmarshalCompactStructWithLimits decodes one struct with caller-selected
// resource limits. Zero-valued limits use conservative package defaults.
func UnmarshalCompactStructWithLimits(data []byte, limits DecodeLimits) (StructValue, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	d := compactDecoder{data: data, limits: limits}
	value, err := d.readStruct(0)
	if err != nil {
		return nil, err
	}
	if d.offset != len(data) {
		return nil, fmt.Errorf("thrift compact: %d trailing bytes", len(data)-d.offset)
	}
	return value, nil
}

type compactWriter struct {
	data  []byte
	items int
}

func (w *compactWriter) writeStruct(value StructValue, depth int) error {
	if depth > maxEncodeDepth {
		return fmt.Errorf("thrift compact: nesting exceeds %d", maxEncodeDepth)
	}
	if len(value) > maxEncodeCollection {
		return fmt.Errorf("struct has %d fields; maximum is %d", len(value), maxEncodeCollection)
	}
	if err := w.reserveItems(len(value)); err != nil {
		return err
	}
	lastFieldID := int16(0)
	for i, field := range value {
		if field.Value == nil {
			return fmt.Errorf("thrift compact: field %d has a nil value", i)
		}
		if err := w.writeField(field, &lastFieldID, depth); err != nil {
			return fmt.Errorf("thrift compact: field %d (id %d): %w", i, field.ID, err)
		}
	}
	w.data = append(w.data, compactStop)
	return nil
}

func (w *compactWriter) writeField(field Field, lastFieldID *int16, depth int) error {
	typeID := field.Value.thriftType()
	compactID, err := toCompactType(typeID)
	if err != nil {
		return err
	}
	if boolean, ok := field.Value.(BoolValue); ok {
		if boolean {
			compactID = compactBoolTrue
		} else {
			compactID = compactBoolFalse
		}
	}

	delta := int32(field.ID) - int32(*lastFieldID)
	if delta > 0 && delta <= 15 {
		w.data = append(w.data, byte(delta<<4)|compactID)
	} else {
		w.data = append(w.data, compactID)
		w.appendZigzag(int64(field.ID))
	}
	*lastFieldID = field.ID

	if typeID == TypeBool {
		return nil
	}
	return w.writeValue(field.Value, depth)
}

func (w *compactWriter) writeValue(value Value, depth int) error {
	if depth > maxEncodeDepth {
		return fmt.Errorf("nesting exceeds %d", maxEncodeDepth)
	}
	switch v := value.(type) {
	case BoolValue:
		if v {
			w.data = append(w.data, compactBoolTrue)
		} else {
			w.data = append(w.data, compactBoolFalse)
		}
	case ByteValue:
		w.data = append(w.data, byte(v))
	case I16Value:
		w.appendZigzag(int64(v))
	case I32Value:
		w.appendZigzag(int64(v))
	case I64Value:
		w.appendZigzag(int64(v))
	case DoubleValue:
		var encoded [8]byte
		binary.LittleEndian.PutUint64(encoded[:], math.Float64bits(float64(v)))
		w.data = append(w.data, encoded[:]...)
	case StringValue:
		if !utf8.ValidString(string(v)) {
			return errors.New("string value is not valid UTF-8")
		}
		return w.appendBinary([]byte(v))
	case BinaryValue:
		return w.appendBinary(v)
	case StructValue:
		return w.writeStruct(v, depth+1)
	case ListValue:
		return w.writeSequence(v.ElementType, v.Values, depth)
	case SetValue:
		return w.writeSequence(v.ElementType, v.Values, depth)
	case MapValue:
		return w.writeMap(v, depth)
	default:
		return fmt.Errorf("unsupported value type %T", value)
	}
	return nil
}

func (w *compactWriter) writeSequence(elementType Type, values []Value, depth int) error {
	if len(values) > maxEncodeCollection {
		return fmt.Errorf("collection has %d items; maximum is %d", len(values), maxEncodeCollection)
	}
	if err := w.reserveItems(len(values)); err != nil {
		return err
	}
	compactID, err := toCompactType(elementType)
	if err != nil {
		return fmt.Errorf("invalid element type %d: %w", elementType, err)
	}
	w.appendCollectionHeader(len(values), compactID)
	for i, value := range values {
		if value == nil || value.thriftType() != elementType {
			return fmt.Errorf("item %d has type %T; expected Thrift type %d", i, value, elementType)
		}
		if err := w.writeValue(value, depth+1); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	return nil
}

func (w *compactWriter) writeMap(value MapValue, depth int) error {
	if len(value.Entries) > maxEncodeCollection {
		return fmt.Errorf("map has %d entries; maximum is %d", len(value.Entries), maxEncodeCollection)
	}
	if err := w.reserveItems(len(value.Entries) * 2); err != nil {
		return err
	}
	w.appendVarint(uint64(len(value.Entries)))
	if len(value.Entries) == 0 {
		return nil
	}
	keyType, err := toCompactType(value.KeyType)
	if err != nil {
		return fmt.Errorf("invalid key type %d: %w", value.KeyType, err)
	}
	valueType, err := toCompactType(value.ValueType)
	if err != nil {
		return fmt.Errorf("invalid value type %d: %w", value.ValueType, err)
	}
	w.data = append(w.data, keyType<<4|valueType)
	for i, entry := range value.Entries {
		if entry.Key == nil || entry.Key.thriftType() != value.KeyType {
			return fmt.Errorf("entry %d has key type %T; expected Thrift type %d", i, entry.Key, value.KeyType)
		}
		if entry.Value == nil || entry.Value.thriftType() != value.ValueType {
			return fmt.Errorf("entry %d has value type %T; expected Thrift type %d", i, entry.Value, value.ValueType)
		}
		if err := w.writeValue(entry.Key, depth+1); err != nil {
			return fmt.Errorf("entry %d key: %w", i, err)
		}
		if err := w.writeValue(entry.Value, depth+1); err != nil {
			return fmt.Errorf("entry %d value: %w", i, err)
		}
	}
	return nil
}

func (w *compactWriter) appendCollectionHeader(size int, typeID byte) {
	if size <= 14 {
		w.data = append(w.data, byte(size<<4)|typeID)
		return
	}
	w.data = append(w.data, 0xf0|typeID)
	w.appendVarint(uint64(size))
}

func (w *compactWriter) appendBinary(value []byte) error {
	if len(value) > math.MaxInt32 {
		return fmt.Errorf("binary value has %d bytes; maximum is %d", len(value), math.MaxInt32)
	}
	w.appendVarint(uint64(len(value)))
	w.data = append(w.data, value...)
	return nil
}

func (w *compactWriter) reserveItems(count int) error {
	if count < 0 || count > maxEncodeCollection-w.items {
		return fmt.Errorf("encoded item count exceeds limit %d", maxEncodeCollection)
	}
	w.items += count
	return nil
}

func (w *compactWriter) appendZigzag(value int64) {
	encoded := uint64(value<<1) ^ uint64(value>>63)
	w.appendVarint(encoded)
}

func (w *compactWriter) appendVarint(value uint64) {
	for value >= 0x80 {
		w.data = append(w.data, byte(value)|0x80)
		value >>= 7
	}
	w.data = append(w.data, byte(value))
}

type compactDecoder struct {
	data        []byte
	offset      int
	items       int
	binaryBytes int
	limits      DecodeLimits
}

func (d *compactDecoder) readStruct(depth int) (StructValue, error) {
	if depth > d.limits.MaxDepth {
		return nil, fmt.Errorf("thrift compact: nesting exceeds %d", d.limits.MaxDepth)
	}
	var fields StructValue
	lastFieldID := int16(0)
	for {
		header, err := d.readByte()
		if err != nil {
			return nil, fmt.Errorf("thrift compact: read field header: %w", err)
		}
		if header == compactStop {
			return fields, nil
		}
		if err := d.reserveItems(1); err != nil {
			return nil, err
		}
		compactID := header & 0x0f
		typeID, err := fromCompactType(compactID)
		if err != nil {
			return nil, err
		}

		delta := int16(header >> 4)
		var fieldID int16
		if delta == 0 {
			rawID, err := d.readZigzag()
			if err != nil {
				return nil, fmt.Errorf("thrift compact: read field id: %w", err)
			}
			if rawID < math.MinInt16 || rawID > math.MaxInt16 {
				return nil, fmt.Errorf("thrift compact: field id %d is outside i16 range", rawID)
			}
			fieldID = int16(rawID)
		} else {
			rawID := int32(lastFieldID) + int32(delta)
			if rawID > math.MaxInt16 {
				return nil, fmt.Errorf("thrift compact: field id delta overflows i16")
			}
			fieldID = int16(rawID)
		}

		var value Value
		if typeID == TypeBool {
			value = BoolValue(compactID == compactBoolTrue)
		} else {
			value, err = d.readValue(typeID, depth)
			if err != nil {
				return nil, fmt.Errorf("thrift compact: field %d: %w", fieldID, err)
			}
		}
		fields = append(fields, Field{ID: fieldID, Value: value})
		lastFieldID = fieldID
	}
}

func (d *compactDecoder) readValue(typeID Type, depth int) (Value, error) {
	if depth > d.limits.MaxDepth {
		return nil, fmt.Errorf("thrift compact: nesting exceeds %d", d.limits.MaxDepth)
	}
	switch typeID {
	case TypeBool:
		value, err := d.readByte()
		if err != nil {
			return nil, err
		}
		if value != compactBoolTrue && value != compactBoolFalse {
			return nil, fmt.Errorf("invalid bool value 0x%02x", value)
		}
		return BoolValue(value == compactBoolTrue), nil
	case TypeByte:
		value, err := d.readByte()
		return ByteValue(int8(value)), err
	case TypeI16:
		value, err := d.readZigzag()
		if err != nil {
			return nil, err
		}
		if value < math.MinInt16 || value > math.MaxInt16 {
			return nil, fmt.Errorf("i16 value %d is out of range", value)
		}
		return I16Value(value), nil
	case TypeI32:
		value, err := d.readZigzag()
		if err != nil {
			return nil, err
		}
		if value < math.MinInt32 || value > math.MaxInt32 {
			return nil, fmt.Errorf("i32 value %d is out of range", value)
		}
		return I32Value(value), nil
	case TypeI64:
		value, err := d.readZigzag()
		return I64Value(value), err
	case TypeDouble:
		encoded, err := d.read(8)
		if err != nil {
			return nil, err
		}
		return DoubleValue(math.Float64frombits(binary.LittleEndian.Uint64(encoded))), nil
	case TypeString:
		value, err := d.readBinary()
		return BinaryValue(value), err
	case TypeStruct:
		value, err := d.readStruct(depth + 1)
		return value, err
	case TypeList, TypeSet:
		return d.readSequence(typeID, depth)
	case TypeMap:
		return d.readMap(depth)
	default:
		return nil, fmt.Errorf("thrift compact: unsupported Thrift type %d", typeID)
	}
}

func (d *compactDecoder) readSequence(kind Type, depth int) (Value, error) {
	header, err := d.readByte()
	if err != nil {
		return nil, err
	}
	size := int(header >> 4)
	if size == 15 {
		rawSize, err := d.readVarint()
		if err != nil {
			return nil, err
		}
		if rawSize > uint64(d.limits.MaxItems) {
			return nil, fmt.Errorf("collection size %d exceeds limit %d", rawSize, d.limits.MaxItems)
		}
		size = int(rawSize)
	}
	if size > d.limits.MaxItems {
		return nil, fmt.Errorf("collection size %d exceeds limit %d", size, d.limits.MaxItems)
	}
	if err := d.reserveItems(size); err != nil {
		return nil, err
	}
	elementType, err := fromCompactType(header & 0x0f)
	if err != nil {
		return nil, err
	}
	values := make([]Value, 0, size)
	for i := 0; i < size; i++ {
		value, err := d.readValue(elementType, depth+1)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
		values = append(values, value)
	}
	if kind == TypeList {
		return ListValue{ElementType: elementType, Values: values}, nil
	}
	return SetValue{ElementType: elementType, Values: values}, nil
}

func (d *compactDecoder) readMap(depth int) (Value, error) {
	rawSize, err := d.readVarint()
	if err != nil {
		return nil, err
	}
	if rawSize > uint64(d.limits.MaxItems) {
		return nil, fmt.Errorf("map size %d exceeds limit %d", rawSize, d.limits.MaxItems)
	}
	size := int(rawSize)
	if size == 0 {
		return MapValue{Entries: []MapEntry{}}, nil
	}
	if size > d.limits.MaxItems/2 {
		return nil, fmt.Errorf("map size %d exceeds remaining item budget", size)
	}
	if err := d.reserveItems(size * 2); err != nil {
		return nil, err
	}
	types, err := d.readByte()
	if err != nil {
		return nil, err
	}
	keyType, err := fromCompactType(types >> 4)
	if err != nil {
		return nil, err
	}
	valueType, err := fromCompactType(types & 0x0f)
	if err != nil {
		return nil, err
	}
	entries := make([]MapEntry, 0, size)
	for i := 0; i < size; i++ {
		key, err := d.readValue(keyType, depth+1)
		if err != nil {
			return nil, fmt.Errorf("entry %d key: %w", i, err)
		}
		value, err := d.readValue(valueType, depth+1)
		if err != nil {
			return nil, fmt.Errorf("entry %d value: %w", i, err)
		}
		entries = append(entries, MapEntry{Key: key, Value: value})
	}
	return MapValue{KeyType: keyType, ValueType: valueType, Entries: entries}, nil
}

func (d *compactDecoder) readBinary() ([]byte, error) {
	size, err := d.readVarint()
	if err != nil {
		return nil, err
	}
	remaining := d.limits.MaxBinaryBytes - d.binaryBytes
	if size > uint64(remaining) {
		return nil, fmt.Errorf("binary payload exceeds aggregate limit %d", d.limits.MaxBinaryBytes)
	}
	value, err := d.read(int(size))
	if err != nil {
		return nil, err
	}
	d.binaryBytes += int(size)
	return append([]byte(nil), value...), nil
}

func (d *compactDecoder) reserveItems(count int) error {
	if count < 0 || count > d.limits.MaxItems-d.items {
		return fmt.Errorf("decoded item count exceeds limit %d", d.limits.MaxItems)
	}
	d.items += count
	return nil
}

func (d *compactDecoder) readZigzag() (int64, error) {
	value, err := d.readVarint()
	if err != nil {
		return 0, err
	}
	return int64(value>>1) ^ -int64(value&1), nil
}

func (d *compactDecoder) readVarint() (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 64; shift += 7 {
		part, err := d.readByte()
		if err != nil {
			return 0, err
		}
		if shift == 63 && part > 1 {
			return 0, errors.New("varint overflows uint64")
		}
		value |= uint64(part&0x7f) << shift
		if part&0x80 == 0 {
			return value, nil
		}
	}
	return 0, errors.New("varint exceeds 10 bytes")
}

func (d *compactDecoder) readByte() (byte, error) {
	if d.offset >= len(d.data) {
		return 0, errors.New("unexpected end of input")
	}
	value := d.data[d.offset]
	d.offset++
	return value, nil
}

func (d *compactDecoder) read(size int) ([]byte, error) {
	if size < 0 || size > len(d.data)-d.offset {
		return nil, fmt.Errorf("need %d bytes with %d remaining", size, len(d.data)-d.offset)
	}
	value := d.data[d.offset : d.offset+size]
	d.offset += size
	return value, nil
}

func normalizeLimits(limits DecodeLimits) (DecodeLimits, error) {
	if limits.MaxDepth == 0 {
		limits.MaxDepth = defaultDecodeDepth
	}
	if limits.MaxItems == 0 {
		limits.MaxItems = defaultDecodeItems
	}
	if limits.MaxBinaryBytes == 0 {
		limits.MaxBinaryBytes = defaultDecodeBinary
	}
	if limits.MaxDepth < 0 || limits.MaxItems < 0 || limits.MaxBinaryBytes < 0 {
		return DecodeLimits{}, errors.New("thrift: decode limits cannot be negative")
	}
	return limits, nil
}

func toCompactType(typeID Type) (byte, error) {
	switch typeID {
	case TypeBool:
		return compactBoolTrue, nil
	case TypeByte:
		return compactByte, nil
	case TypeI16:
		return compactI16, nil
	case TypeI32:
		return compactI32, nil
	case TypeI64:
		return compactI64, nil
	case TypeDouble:
		return compactDouble, nil
	case TypeString:
		return compactBinary, nil
	case TypeList:
		return compactList, nil
	case TypeSet:
		return compactSet, nil
	case TypeMap:
		return compactMap, nil
	case TypeStruct:
		return compactStruct, nil
	default:
		return 0, fmt.Errorf("thrift compact: unsupported Thrift type %d", typeID)
	}
}

func fromCompactType(compactID byte) (Type, error) {
	switch compactID {
	case compactBoolTrue, compactBoolFalse:
		return TypeBool, nil
	case compactByte:
		return TypeByte, nil
	case compactI16:
		return TypeI16, nil
	case compactI32:
		return TypeI32, nil
	case compactI64:
		return TypeI64, nil
	case compactDouble:
		return TypeDouble, nil
	case compactBinary:
		return TypeString, nil
	case compactList:
		return TypeList, nil
	case compactSet:
		return TypeSet, nil
	case compactMap:
		return TypeMap, nil
	case compactStruct:
		return TypeStruct, nil
	default:
		return 0, fmt.Errorf("thrift compact: invalid compact type %d", compactID)
	}
}
