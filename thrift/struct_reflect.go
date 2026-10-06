package thrift

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type fieldTag struct {
	id        int16
	typeID    Type
	keyType   Type
	valueType Type
	unknown   bool
}

// MarshalArgs encodes a tagged Go struct as a Thrift args struct. Struct fields
// use thrift tags in the form `thrift:"fieldID,type"`; list, set, and map tags
// append their element or key/value Thrift types. Nil pointers, slices, and
// maps are omitted, while non-nil empty collections remain present.
func MarshalArgs(value any) (StructValue, error) {
	if value == nil {
		return nil, nil
	}
	if fields, ok := value.(StructValue); ok {
		return fields, nil
	}
	reflected := reflect.ValueOf(value)
	for reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Interface {
		if reflected.IsNil() {
			return nil, nil
		}
		reflected = reflected.Elem()
	}
	if reflected.Kind() != reflect.Struct {
		return nil, fmt.Errorf("thrift: args must be a struct, got %T", value)
	}
	return marshalTaggedStruct(reflected)
}

// UnmarshalStructValue populates a tagged Go struct from a decoded Thrift
// struct. target must be a non-nil pointer to a struct.
func UnmarshalStructValue(fields StructValue, target any) error {
	if target == nil {
		return fmt.Errorf("thrift: target is nil")
	}
	reflected := reflect.ValueOf(target)
	if reflected.Kind() != reflect.Pointer || reflected.IsNil() || reflected.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("thrift: target must be a non-nil pointer to a struct")
	}
	return unmarshalTaggedStruct(fields, reflected.Elem())
}

func marshalTaggedStruct(value reflect.Value) (StructValue, error) {
	type sortableField struct {
		field Field
		name  string
	}
	encoded := make([]sortableField, 0, value.NumField())
	for index := 0; index < value.NumField(); index++ {
		definition := value.Type().Field(index)
		if definition.PkgPath != "" {
			continue
		}
		tag, found, err := parseFieldTag(definition.Tag.Get("thrift"))
		if err != nil {
			return nil, fmt.Errorf("thrift: field %s: %w", definition.Name, err)
		}
		if !found {
			continue
		}
		fieldValue := value.Field(index)
		if isNilValue(fieldValue) {
			continue
		}
		thriftValue, present, err := marshalTaggedValue(tag, fieldValue)
		if err != nil {
			return nil, fmt.Errorf("thrift: field %s (id %d): %w", definition.Name, tag.id, err)
		}
		if !present {
			continue
		}
		encoded = append(encoded, sortableField{
			field: Field{ID: tag.id, Value: thriftValue},
			name:  definition.Name,
		})
	}
	sort.SliceStable(encoded, func(i, j int) bool {
		return encoded[i].field.ID < encoded[j].field.ID
	})
	fields := make(StructValue, len(encoded))
	for index, item := range encoded {
		fields[index] = item.field
	}
	return fields, nil
}

func marshalTaggedValue(tag fieldTag, value reflect.Value) (Value, bool, error) {
	value = indirectValue(value)
	if !value.IsValid() {
		return nil, false, nil
	}
	if tag.unknown {
		if value.CanInterface() {
			if raw, ok := value.Interface().(Value); ok {
				return raw, true, nil
			}
			if raw, ok := value.Interface().(StructValue); ok {
				return raw, true, nil
			}
		}
		return nil, false, fmt.Errorf("field uses an unsupported upstream type descriptor")
	}

	switch tag.typeID {
	case TypeList, TypeSet:
		if value.Kind() != reflect.Slice && value.Kind() != reflect.Array {
			return nil, false, fmt.Errorf("want a slice, got %s", value.Kind())
		}
		values := make([]Value, 0, value.Len())
		for index := 0; index < value.Len(); index++ {
			item, err := marshalWireValue(tag.keyType, value.Index(index))
			if err != nil {
				return nil, false, fmt.Errorf("item %d: %w", index, err)
			}
			values = append(values, item)
		}
		if tag.typeID == TypeList {
			return ListValue{ElementType: tag.keyType, Values: values}, true, nil
		}
		return SetValue{ElementType: tag.keyType, Values: values}, true, nil
	case TypeMap:
		if value.Kind() != reflect.Map {
			return nil, false, fmt.Errorf("want a map, got %s", value.Kind())
		}
		keys := value.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			return fmt.Sprint(keys[i].Interface()) < fmt.Sprint(keys[j].Interface())
		})
		entries := make([]MapEntry, 0, len(keys))
		for _, key := range keys {
			encodedKey, err := marshalWireValue(tag.keyType, key)
			if err != nil {
				return nil, false, fmt.Errorf("map key: %w", err)
			}
			encodedValue, err := marshalWireValue(tag.valueType, value.MapIndex(key))
			if err != nil {
				return nil, false, fmt.Errorf("map value for %v: %w", key.Interface(), err)
			}
			entries = append(entries, MapEntry{Key: encodedKey, Value: encodedValue})
		}
		return MapValue{KeyType: tag.keyType, ValueType: tag.valueType, Entries: entries}, true, nil
	default:
		encoded, err := marshalWireValue(tag.typeID, value)
		if err != nil {
			return nil, false, err
		}
		if tag.typeID == TypeStruct && len(encoded.(StructValue)) == 0 {
			return nil, false, nil
		}
		return encoded, true, nil
	}
}

func marshalWireValue(typeID Type, value reflect.Value) (Value, error) {
	value = indirectValue(value)
	if !value.IsValid() {
		return nil, fmt.Errorf("nil value")
	}
	if value.CanInterface() {
		if raw, ok := value.Interface().(Value); ok {
			rawType, known := valueType(raw)
			if !known {
				return nil, fmt.Errorf("unsupported Thrift value %T", raw)
			}
			if rawType != typeID {
				return nil, fmt.Errorf("value has thrift type %d, want %d", rawType, typeID)
			}
			return raw, nil
		}
		if raw, ok := value.Interface().(StructValue); ok && typeID == TypeStruct {
			return raw, nil
		}
	}

	switch typeID {
	case TypeBool:
		if value.Kind() != reflect.Bool {
			return nil, fmt.Errorf("want bool, got %s", value.Kind())
		}
		return BoolValue(value.Bool()), nil
	case TypeByte:
		number, err := signedValue(value)
		if err != nil {
			return nil, err
		}
		if number < math.MinInt8 || number > math.MaxInt8 {
			return nil, fmt.Errorf("value %d is outside i8 range", number)
		}
		return ByteValue(number), nil
	case TypeI16:
		number, err := signedValue(value)
		if err != nil {
			return nil, err
		}
		if number < math.MinInt16 || number > math.MaxInt16 {
			return nil, fmt.Errorf("value %d is outside i16 range", number)
		}
		return I16Value(number), nil
	case TypeI32:
		number, err := signedValue(value)
		if err != nil {
			return nil, err
		}
		if number < math.MinInt32 || number > math.MaxInt32 {
			return nil, fmt.Errorf("value %d is outside i32 range", number)
		}
		return I32Value(number), nil
	case TypeI64:
		number, err := signedValue(value)
		if err != nil {
			return nil, err
		}
		return I64Value(number), nil
	case TypeDouble:
		if value.Kind() != reflect.Float32 && value.Kind() != reflect.Float64 {
			return nil, fmt.Errorf("want float, got %s", value.Kind())
		}
		return DoubleValue(value.Float()), nil
	case TypeString:
		switch value.Kind() {
		case reflect.String:
			return StringValue(value.String()), nil
		case reflect.Slice:
			if value.Type().Elem().Kind() != reflect.Uint8 {
				return nil, fmt.Errorf("want string or byte slice, got %s", value.Type())
			}
			return BinaryValue(append([]byte(nil), value.Bytes()...)), nil
		default:
			return nil, fmt.Errorf("want string or byte slice, got %s", value.Kind())
		}
	case TypeStruct:
		if value.Kind() != reflect.Struct {
			return nil, fmt.Errorf("want struct, got %s", value.Kind())
		}
		return marshalTaggedStruct(value)
	default:
		return nil, fmt.Errorf("unsupported thrift type %d", typeID)
	}
}

func valueType(value Value) (Type, bool) {
	switch value.(type) {
	case BoolValue:
		return TypeBool, true
	case ByteValue:
		return TypeByte, true
	case I16Value:
		return TypeI16, true
	case I32Value:
		return TypeI32, true
	case I64Value:
		return TypeI64, true
	case DoubleValue:
		return TypeDouble, true
	case StringValue, BinaryValue:
		return TypeString, true
	case StructValue:
		return TypeStruct, true
	case ListValue:
		return TypeList, true
	case SetValue:
		return TypeSet, true
	case MapValue:
		return TypeMap, true
	default:
		return 0, false
	}
}

func unmarshalTaggedStruct(fields StructValue, target reflect.Value) error {
	byID := make(map[int16]Value, len(fields))
	for _, field := range fields {
		byID[field.ID] = field.Value
	}
	for index := 0; index < target.NumField(); index++ {
		definition := target.Type().Field(index)
		if definition.PkgPath != "" {
			continue
		}
		tag, found, err := parseFieldTag(definition.Tag.Get("thrift"))
		if err != nil {
			return fmt.Errorf("thrift: field %s: %w", definition.Name, err)
		}
		if !found {
			continue
		}
		value, ok := byID[tag.id]
		if !ok {
			continue
		}
		if tag.unknown {
			if target.Field(index).Kind() == reflect.Interface && target.Field(index).CanSet() {
				target.Field(index).Set(reflect.ValueOf(value))
			}
			continue
		}
		if err := unmarshalTaggedValue(tag, value, target.Field(index)); err != nil {
			return fmt.Errorf("thrift: field %s (id %d): %w", definition.Name, tag.id, err)
		}
	}
	return nil
}

func unmarshalTaggedValue(tag fieldTag, source Value, target reflect.Value) error {
	if target.Kind() == reflect.Pointer {
		if source == nil {
			target.SetZero()
			return nil
		}
		target.Set(reflect.New(target.Type().Elem()))
		return unmarshalTaggedValue(tag, source, target.Elem())
	}
	if target.Kind() == reflect.Interface {
		if source == nil {
			target.SetZero()
			return nil
		}
		raw := reflect.ValueOf(source)
		if raw.Type().AssignableTo(target.Type()) || target.NumMethod() == 0 {
			target.Set(raw)
			return nil
		}
		return fmt.Errorf("decoded value %T does not implement %s", source, target.Type())
	}
	switch tag.typeID {
	case TypeList, TypeSet:
		var items []Value
		if tag.typeID == TypeList {
			sequence, ok := source.(ListValue)
			if !ok {
				return fmt.Errorf("want list, got %T", source)
			}
			items = sequence.Values
		} else {
			sequence, ok := source.(SetValue)
			if !ok {
				return fmt.Errorf("want set, got %T", source)
			}
			items = sequence.Values
		}
		if target.Kind() != reflect.Slice {
			return fmt.Errorf("want slice destination, got %s", target.Kind())
		}
		result := reflect.MakeSlice(target.Type(), len(items), len(items))
		for index, item := range items {
			if err := unmarshalWireValue(tag.keyType, item, result.Index(index)); err != nil {
				return fmt.Errorf("item %d: %w", index, err)
			}
		}
		target.Set(result)
		return nil
	case TypeMap:
		mapping, ok := source.(MapValue)
		if !ok {
			return fmt.Errorf("want map, got %T", source)
		}
		if target.Kind() != reflect.Map {
			return fmt.Errorf("want map destination, got %s", target.Kind())
		}
		result := reflect.MakeMapWithSize(target.Type(), len(mapping.Entries))
		for index, entry := range mapping.Entries {
			key := reflect.New(target.Type().Key()).Elem()
			if err := unmarshalWireValue(tag.keyType, entry.Key, key); err != nil {
				return fmt.Errorf("entry %d key: %w", index, err)
			}
			value := reflect.New(target.Type().Elem()).Elem()
			if err := unmarshalWireValue(tag.valueType, entry.Value, value); err != nil {
				return fmt.Errorf("entry %d value: %w", index, err)
			}
			result.SetMapIndex(key, value)
		}
		target.Set(result)
		return nil
	default:
		return unmarshalWireValue(tag.typeID, source, target)
	}
}

func unmarshalWireValue(typeID Type, source Value, target reflect.Value) error {
	if target.Kind() == reflect.Pointer {
		if source == nil {
			target.SetZero()
			return nil
		}
		target.Set(reflect.New(target.Type().Elem()))
		return unmarshalWireValue(typeID, source, target.Elem())
	}
	if target.Kind() == reflect.Interface {
		if source == nil {
			target.SetZero()
			return nil
		}
		raw := reflect.ValueOf(source)
		if target.NumMethod() == 0 || raw.Type().AssignableTo(target.Type()) {
			target.Set(raw)
			return nil
		}
		return fmt.Errorf("decoded value %T does not implement %s", source, target.Type())
	}
	switch typeID {
	case TypeBool:
		value, ok := source.(BoolValue)
		if !ok || target.Kind() != reflect.Bool {
			return fmt.Errorf("cannot decode %T into %s", source, target.Type())
		}
		target.SetBool(bool(value))
	case TypeByte, TypeI16, TypeI32, TypeI64:
		number, err := signedThriftValue(source)
		if err != nil {
			return err
		}
		if target.Kind() < reflect.Int || target.Kind() > reflect.Int64 || target.OverflowInt(number) {
			return fmt.Errorf("integer %d does not fit %s", number, target.Type())
		}
		target.SetInt(number)
	case TypeDouble:
		value, ok := source.(DoubleValue)
		if !ok || target.Kind() != reflect.Float32 && target.Kind() != reflect.Float64 {
			return fmt.Errorf("cannot decode %T into %s", source, target.Type())
		}
		if target.OverflowFloat(float64(value)) {
			return fmt.Errorf("float %v does not fit %s", value, target.Type())
		}
		target.SetFloat(float64(value))
	case TypeString:
		var data []byte
		switch value := source.(type) {
		case StringValue:
			data = []byte(value)
		case BinaryValue:
			data = value
		default:
			return fmt.Errorf("cannot decode %T as a string", source)
		}
		switch target.Kind() {
		case reflect.String:
			target.SetString(string(data))
		case reflect.Slice:
			if target.Type().Elem().Kind() != reflect.Uint8 {
				return fmt.Errorf("cannot decode string into %s", target.Type())
			}
			target.SetBytes(append([]byte(nil), data...))
		default:
			return fmt.Errorf("cannot decode string into %s", target.Type())
		}
	case TypeStruct:
		fields, ok := source.(StructValue)
		if !ok || target.Kind() != reflect.Struct {
			return fmt.Errorf("cannot decode %T into %s", source, target.Type())
		}
		return unmarshalTaggedStruct(fields, target)
	default:
		return fmt.Errorf("unsupported thrift type %d", typeID)
	}
	return nil
}

func parseFieldTag(value string) (fieldTag, bool, error) {
	if value == "" || value == "-" {
		return fieldTag{}, false, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) < 2 {
		return fieldTag{}, false, fmt.Errorf("invalid thrift tag %q", value)
	}
	fieldID, err := strconv.Atoi(parts[0])
	if err != nil || fieldID < math.MinInt16 || fieldID > math.MaxInt16 {
		return fieldTag{}, false, fmt.Errorf("invalid field id in thrift tag %q", value)
	}
	tag := fieldTag{id: int16(fieldID)}
	if parts[1] == "unknown" {
		tag.unknown = true
		return tag, true, nil
	}
	typeID, err := strconv.Atoi(parts[1])
	if err != nil {
		return fieldTag{}, false, fmt.Errorf("invalid type in thrift tag %q", value)
	}
	tag.typeID = Type(typeID)
	switch tag.typeID {
	case TypeList, TypeSet:
		if len(parts) != 3 {
			return fieldTag{}, false, fmt.Errorf("collection tag must include an element type")
		}
		elementType, err := strconv.Atoi(parts[2])
		if err != nil {
			return fieldTag{}, false, fmt.Errorf("invalid collection element type in thrift tag %q", value)
		}
		tag.keyType = Type(elementType)
	case TypeMap:
		if len(parts) != 4 {
			return fieldTag{}, false, fmt.Errorf("map tag must include key and value types")
		}
		keyType, keyErr := strconv.Atoi(parts[2])
		valueType, valueErr := strconv.Atoi(parts[3])
		if keyErr != nil || valueErr != nil {
			return fieldTag{}, false, fmt.Errorf("invalid map types in thrift tag %q", value)
		}
		tag.keyType = Type(keyType)
		tag.valueType = Type(valueType)
	}
	return tag, true, nil
}

func indirectValue(value reflect.Value) reflect.Value {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	return value
}

func isNilValue(value reflect.Value) bool {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return true
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func signedValue(value reflect.Value) (int64, error) {
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		unsigned := value.Uint()
		if unsigned > math.MaxInt64 {
			return 0, fmt.Errorf("integer %d exceeds i64 range", unsigned)
		}
		return int64(unsigned), nil
	default:
		return 0, fmt.Errorf("want integer, got %s", value.Kind())
	}
}

func signedThriftValue(value Value) (int64, error) {
	switch number := value.(type) {
	case ByteValue:
		return int64(number), nil
	case I16Value:
		return int64(number), nil
	case I32Value:
		return int64(number), nil
	case I64Value:
		return int64(number), nil
	default:
		return 0, fmt.Errorf("want thrift integer, got %T", value)
	}
}
