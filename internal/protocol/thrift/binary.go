package thrift

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// MarshalBinaryStruct encodes one Thrift struct without a message envelope.
func MarshalBinaryStruct(value StructValue) ([]byte, error) {
	w := binaryWriter{}
	if err := w.writeStruct(value, 0); err != nil {
		return nil, err
	}
	return w.data, nil
}

// MarshalBinaryRequest encodes a strict Thrift CALL header, args struct, and
// LINEJS's trailing zero byte.
func MarshalBinaryRequest(method string, args StructValue) ([]byte, error) {
	if !utf8.ValidString(method) {
		return nil, fmt.Errorf("thrift binary: method name is not valid UTF-8")
	}
	if len(method) > math.MaxInt32 {
		return nil, fmt.Errorf("thrift binary: method name is %d bytes; maximum is %d", len(method), math.MaxInt32)
	}

	request := make([]byte, 0, 13+len(method)+len(args)*5)
	request = append(request, 0x80, 0x01, 0x00, 0x01)
	request = binary.BigEndian.AppendUint32(request, uint32(len(method)))
	request = append(request, method...)
	request = append(request, 0x00, 0x00, 0x00, 0x00)
	if len(args) != 0 {
		body, err := MarshalBinaryStruct(args)
		if err != nil {
			return nil, err
		}
		request = append(request, body...)
	}
	request = append(request, 0x00)
	return request, nil
}

// UnmarshalBinaryStruct decodes exactly one Thrift struct without a message
// envelope and rejects trailing bytes and inputs over the default limits.
func UnmarshalBinaryStruct(data []byte) (StructValue, error) {
	return UnmarshalBinaryStructWithLimits(data, DecodeLimits{})
}

// UnmarshalBinaryStructWithLimits decodes one struct with caller-selected
// resource limits. Zero-valued limits select package defaults.
func UnmarshalBinaryStructWithLimits(data []byte, limits DecodeLimits) (StructValue, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return nil, err
	}
	d := binaryDecoder{data: data, limits: limits}
	value, err := d.readStruct(0)
	if err != nil {
		return nil, err
	}
	if d.offset != len(data) {
		return nil, fmt.Errorf("thrift binary: %d trailing bytes", len(data)-d.offset)
	}
	return value, nil
}

type binaryWriter struct {
	data  []byte
	items int
}

func (w *binaryWriter) writeStruct(value StructValue, depth int) error {
	if depth > maxEncodeDepth {
		return fmt.Errorf("thrift binary: nesting exceeds %d", maxEncodeDepth)
	}
	if len(value) > maxEncodeCollection {
		return fmt.Errorf("thrift binary: struct has %d fields; maximum is %d", len(value), maxEncodeCollection)
	}
	if err := w.reserveItems(len(value)); err != nil {
		return err
	}
	for index, field := range value {
		if field.Value == nil {
			return fmt.Errorf("thrift binary: field %d has a nil value", index)
		}
		wireType, err := toBinaryType(field.Value.thriftType())
		if err != nil {
			return fmt.Errorf("thrift binary: field %d (id %d): %w", index, field.ID, err)
		}
		w.data = append(w.data, wireType)
		w.data = binary.BigEndian.AppendUint16(w.data, uint16(field.ID))
		if err := w.writeValue(field.Value, depth); err != nil {
			return fmt.Errorf("thrift binary: field %d (id %d): %w", index, field.ID, err)
		}
	}
	w.data = append(w.data, byte(TypeStop))
	return nil
}

func (w *binaryWriter) writeValue(value Value, depth int) error {
	if depth > maxEncodeDepth {
		return fmt.Errorf("nesting exceeds %d", maxEncodeDepth)
	}
	switch v := value.(type) {
	case BoolValue:
		if v {
			w.data = append(w.data, 1)
		} else {
			w.data = append(w.data, 0)
		}
	case ByteValue:
		w.data = append(w.data, byte(v))
	case I16Value:
		w.data = binary.BigEndian.AppendUint16(w.data, uint16(v))
	case I32Value:
		w.data = binary.BigEndian.AppendUint32(w.data, uint32(v))
	case I64Value:
		w.data = binary.BigEndian.AppendUint64(w.data, uint64(v))
	case DoubleValue:
		w.data = binary.BigEndian.AppendUint64(w.data, math.Float64bits(float64(v)))
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

func (w *binaryWriter) writeSequence(elementType Type, values []Value, depth int) error {
	if len(values) > maxEncodeCollection || len(values) > math.MaxInt32 {
		return fmt.Errorf("collection has %d items; maximum is %d", len(values), maxEncodeCollection)
	}
	if err := w.reserveItems(len(values)); err != nil {
		return err
	}
	wireType, err := toBinaryType(elementType)
	if err != nil {
		return fmt.Errorf("invalid element type %d: %w", elementType, err)
	}
	w.data = append(w.data, wireType)
	w.data = binary.BigEndian.AppendUint32(w.data, uint32(len(values)))
	for index, value := range values {
		if value == nil || value.thriftType() != elementType {
			return fmt.Errorf("item %d has type %T; expected thrift type %d", index, value, elementType)
		}
		if err := w.writeValue(value, depth+1); err != nil {
			return fmt.Errorf("item %d: %w", index, err)
		}
	}
	return nil
}

func (w *binaryWriter) writeMap(value MapValue, depth int) error {
	if len(value.Entries) > maxEncodeCollection || len(value.Entries) > math.MaxInt32 {
		return fmt.Errorf("map has %d entries; maximum is %d", len(value.Entries), maxEncodeCollection)
	}
	if err := w.reserveItems(len(value.Entries) * 2); err != nil {
		return err
	}
	keyType, err := toBinaryType(value.KeyType)
	if err != nil {
		return fmt.Errorf("invalid key type %d: %w", value.KeyType, err)
	}
	valueType, err := toBinaryType(value.ValueType)
	if err != nil {
		return fmt.Errorf("invalid value type %d: %w", value.ValueType, err)
	}
	w.data = append(w.data, keyType, valueType)
	w.data = binary.BigEndian.AppendUint32(w.data, uint32(len(value.Entries)))
	for index, entry := range value.Entries {
		if entry.Key == nil || entry.Key.thriftType() != value.KeyType {
			return fmt.Errorf("entry %d has key type %T; expected thrift type %d", index, entry.Key, value.KeyType)
		}
		if entry.Value == nil || entry.Value.thriftType() != value.ValueType {
			return fmt.Errorf("entry %d has value type %T; expected thrift type %d", index, entry.Value, value.ValueType)
		}
		if err := w.writeValue(entry.Key, depth+1); err != nil {
			return fmt.Errorf("entry %d key: %w", index, err)
		}
		if err := w.writeValue(entry.Value, depth+1); err != nil {
			return fmt.Errorf("entry %d value: %w", index, err)
		}
	}
	return nil
}

func (w *binaryWriter) appendBinary(value []byte) error {
	if len(value) > math.MaxInt32 {
		return fmt.Errorf("binary value has %d bytes; maximum is %d", len(value), math.MaxInt32)
	}
	w.data = binary.BigEndian.AppendUint32(w.data, uint32(len(value)))
	w.data = append(w.data, value...)
	return nil
}

func (w *binaryWriter) reserveItems(count int) error {
	if count < 0 || count > maxEncodeCollection-w.items {
		return fmt.Errorf("encoded item count exceeds limit %d", maxEncodeCollection)
	}
	w.items += count
	return nil
}

type binaryDecoder struct {
	data        []byte
	offset      int
	items       int
	binaryBytes int
	limits      DecodeLimits
}

func (d *binaryDecoder) readStruct(depth int) (StructValue, error) {
	if depth > d.limits.MaxDepth {
		return nil, fmt.Errorf("thrift binary: nesting exceeds %d", d.limits.MaxDepth)
	}
	fields := make(StructValue, 0)
	for {
		wireType, err := d.readByte()
		if err != nil {
			return nil, fmt.Errorf("thrift binary: read field type: %w", err)
		}
		if Type(wireType) == TypeStop {
			return fields, nil
		}
		if err := d.reserveItems(1); err != nil {
			return nil, err
		}
		typeID, err := fromBinaryType(wireType)
		if err != nil {
			return nil, err
		}
		fieldID, err := d.readI16()
		if err != nil {
			return nil, fmt.Errorf("thrift binary: read field id: %w", err)
		}
		value, err := d.readValue(typeID, depth)
		if err != nil {
			return nil, fmt.Errorf("thrift binary: field %d: %w", fieldID, err)
		}
		fields = append(fields, Field{ID: fieldID, Value: value})
	}
}

func (d *binaryDecoder) readValue(typeID Type, depth int) (Value, error) {
	if depth > d.limits.MaxDepth {
		return nil, fmt.Errorf("thrift binary: nesting exceeds %d", d.limits.MaxDepth)
	}
	switch typeID {
	case TypeBool:
		value, err := d.readByte()
		return BoolValue(value != 0), err
	case TypeByte:
		value, err := d.readByte()
		return ByteValue(int8(value)), err
	case TypeI16:
		value, err := d.readI16()
		return I16Value(value), err
	case TypeI32:
		value, err := d.readI32()
		return I32Value(value), err
	case TypeI64:
		value, err := d.readI64()
		return I64Value(value), err
	case TypeDouble:
		value, err := d.read(8)
		if err != nil {
			return nil, err
		}
		return DoubleValue(math.Float64frombits(binary.BigEndian.Uint64(value))), nil
	case TypeString:
		value, err := d.readBinary()
		return BinaryValue(value), err
	case TypeStruct:
		return d.readStruct(depth + 1)
	case TypeList, TypeSet:
		return d.readSequence(typeID, depth)
	case TypeMap:
		return d.readMap(depth)
	default:
		return nil, fmt.Errorf("thrift binary: unsupported thrift type %d", typeID)
	}
}

func (d *binaryDecoder) readSequence(kind Type, depth int) (Value, error) {
	wireType, err := d.readByte()
	if err != nil {
		return nil, err
	}
	elementType, err := fromBinaryType(wireType)
	if err != nil {
		return nil, fmt.Errorf("invalid element type: %w", err)
	}
	size, err := d.readCollectionSize()
	if err != nil {
		return nil, err
	}
	if err := d.reserveItems(size); err != nil {
		return nil, err
	}
	values := make([]Value, 0, size)
	for index := 0; index < size; index++ {
		value, err := d.readValue(elementType, depth+1)
		if err != nil {
			return nil, fmt.Errorf("item %d: %w", index, err)
		}
		values = append(values, value)
	}
	if kind == TypeList {
		return ListValue{ElementType: elementType, Values: values}, nil
	}
	return SetValue{ElementType: elementType, Values: values}, nil
}

func (d *binaryDecoder) readMap(depth int) (Value, error) {
	keyWireType, err := d.readByte()
	if err != nil {
		return nil, err
	}
	valueWireType, err := d.readByte()
	if err != nil {
		return nil, err
	}
	keyType, err := fromBinaryType(keyWireType)
	if err != nil {
		return nil, fmt.Errorf("invalid key type: %w", err)
	}
	valueType, err := fromBinaryType(valueWireType)
	if err != nil {
		return nil, fmt.Errorf("invalid value type: %w", err)
	}
	size, err := d.readCollectionSize()
	if err != nil {
		return nil, err
	}
	if size > d.limits.MaxItems/2 {
		return nil, fmt.Errorf("map size %d exceeds remaining item budget", size)
	}
	if err := d.reserveItems(size * 2); err != nil {
		return nil, err
	}
	entries := make([]MapEntry, 0, size)
	for index := 0; index < size; index++ {
		key, err := d.readValue(keyType, depth+1)
		if err != nil {
			return nil, fmt.Errorf("entry %d key: %w", index, err)
		}
		value, err := d.readValue(valueType, depth+1)
		if err != nil {
			return nil, fmt.Errorf("entry %d value: %w", index, err)
		}
		entries = append(entries, MapEntry{Key: key, Value: value})
	}
	return MapValue{KeyType: keyType, ValueType: valueType, Entries: entries}, nil
}

func (d *binaryDecoder) readBinary() ([]byte, error) {
	size, err := d.readI32()
	if err != nil {
		return nil, err
	}
	if size < 0 {
		return nil, fmt.Errorf("negative binary length %d", size)
	}
	remaining := d.limits.MaxBinaryBytes - d.binaryBytes
	if int(size) > remaining {
		return nil, fmt.Errorf("binary payload exceeds aggregate limit %d", d.limits.MaxBinaryBytes)
	}
	value, err := d.read(int(size))
	if err != nil {
		return nil, err
	}
	d.binaryBytes += int(size)
	return append([]byte(nil), value...), nil
}

func (d *binaryDecoder) readCollectionSize() (int, error) {
	size, err := d.readI32()
	if err != nil {
		return 0, err
	}
	if size < 0 {
		return 0, fmt.Errorf("negative collection size %d", size)
	}
	if int(size) > d.limits.MaxItems {
		return 0, fmt.Errorf("collection size %d exceeds limit %d", size, d.limits.MaxItems)
	}
	return int(size), nil
}

func (d *binaryDecoder) reserveItems(count int) error {
	if count < 0 || count > d.limits.MaxItems-d.items {
		return fmt.Errorf("decoded item count exceeds limit %d", d.limits.MaxItems)
	}
	d.items += count
	return nil
}

func (d *binaryDecoder) readByte() (byte, error) {
	if d.offset >= len(d.data) {
		return 0, errors.New("unexpected end of input")
	}
	value := d.data[d.offset]
	d.offset++
	return value, nil
}

func (d *binaryDecoder) readI16() (int16, error) {
	value, err := d.read(2)
	if err != nil {
		return 0, err
	}
	return int16(binary.BigEndian.Uint16(value)), nil
}

func (d *binaryDecoder) readI32() (int32, error) {
	value, err := d.read(4)
	if err != nil {
		return 0, err
	}
	return int32(binary.BigEndian.Uint32(value)), nil
}

func (d *binaryDecoder) readI64() (int64, error) {
	value, err := d.read(8)
	if err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(value)), nil
}

func (d *binaryDecoder) read(size int) ([]byte, error) {
	if size < 0 || size > len(d.data)-d.offset {
		return nil, fmt.Errorf("need %d bytes with %d remaining", size, len(d.data)-d.offset)
	}
	value := d.data[d.offset : d.offset+size]
	d.offset += size
	return value, nil
}

func toBinaryType(typeID Type) (byte, error) {
	switch typeID {
	case TypeBool, TypeByte, TypeDouble, TypeI16, TypeI32, TypeI64, TypeString,
		TypeStruct, TypeMap, TypeSet, TypeList:
		return byte(typeID), nil
	default:
		return 0, fmt.Errorf("unsupported Thrift type %d", typeID)
	}
}

func fromBinaryType(wireType byte) (Type, error) {
	typeID := Type(wireType)
	if _, err := toBinaryType(typeID); err != nil {
		return 0, fmt.Errorf("thrift binary: invalid type %d", wireType)
	}
	return typeID, nil
}
