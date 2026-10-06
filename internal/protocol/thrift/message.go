package thrift

import (
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf8"
)

// Protocol selects the Thrift protocol used for a message.
type Protocol uint8

const (
	ProtocolBinary  Protocol = 3
	ProtocolCompact Protocol = 4
)

// MessageType is the Thrift message envelope type.
type MessageType uint8

const (
	MessageUnknown   MessageType = 0
	MessageCall      MessageType = 1
	MessageReply     MessageType = 2
	MessageException MessageType = 3
	MessageOneway    MessageType = 4
)

// Message is a decoded or encoded Thrift message.
type Message struct {
	Method     string
	Type       MessageType
	SequenceID int32
	Args       StructValue
}

// MarshalMessage encodes a Thrift message without LINEJS's request terminator.
func MarshalMessage(protocol Protocol, message Message) ([]byte, error) {
	if err := validateMessage(message); err != nil {
		return nil, err
	}
	switch protocol {
	case ProtocolBinary:
		return marshalBinaryMessage(message)
	case ProtocolCompact:
		return marshalCompactMessage(message)
	default:
		return nil, fmt.Errorf("thrift: unsupported protocol %d", protocol)
	}
}

// UnmarshalMessage decodes one Thrift message. It also accepts the single zero
// terminator appended by LINEJS to request bodies.
func UnmarshalMessage(protocol Protocol, data []byte) (Message, error) {
	return UnmarshalMessageWithLimits(protocol, data, DecodeLimits{})
}

// UnmarshalMessageWithLimits decodes one message with caller-selected resource
// limits. Zero-valued limits select package defaults.
func UnmarshalMessageWithLimits(protocol Protocol, data []byte, limits DecodeLimits) (Message, error) {
	limits, err := normalizeLimits(limits)
	if err != nil {
		return Message{}, err
	}
	switch protocol {
	case ProtocolBinary:
		return unmarshalBinaryMessage(data, limits)
	case ProtocolCompact:
		return unmarshalCompactMessage(data, limits)
	default:
		return Message{}, fmt.Errorf("thrift: unsupported protocol %d", protocol)
	}
}

func marshalBinaryMessage(message Message) ([]byte, error) {
	if !utf8.ValidString(message.Method) {
		return nil, fmt.Errorf("thrift binary: method name is not valid UTF-8")
	}
	if len(message.Method) > math.MaxInt32 {
		return nil, fmt.Errorf("thrift binary: method name is %d bytes; maximum is %d", len(message.Method), math.MaxInt32)
	}
	body, err := MarshalBinaryStruct(message.Args)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 12+len(message.Method)+len(body))
	data = binary.BigEndian.AppendUint32(data, uint32(0x80010000)|uint32(message.Type))
	data = binary.BigEndian.AppendUint32(data, uint32(len(message.Method)))
	data = append(data, message.Method...)
	data = binary.BigEndian.AppendUint32(data, uint32(message.SequenceID))
	data = append(data, body...)
	return data, nil
}

func marshalCompactMessage(message Message) ([]byte, error) {
	if !utf8.ValidString(message.Method) {
		return nil, fmt.Errorf("thrift compact: method name is not valid UTF-8")
	}
	if len(message.Method) > math.MaxUint8 {
		return nil, fmt.Errorf("thrift compact: method name is %d bytes; maximum is 255", len(message.Method))
	}
	body, err := MarshalCompactStruct(message.Args)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 2+5+len(message.Method)+len(body))
	data = append(data, 0x82, byte(message.Type<<5)|0x01)
	data = appendUnsignedVarint(data, uint64(uint32(message.SequenceID)))
	data = appendUnsignedVarint(data, uint64(len(message.Method)))
	data = append(data, message.Method...)
	data = append(data, body...)
	return data, nil
}

func unmarshalBinaryMessage(data []byte, limits DecodeLimits) (Message, error) {
	d := binaryDecoder{data: data, limits: limits}
	first, err := d.readI32()
	if err != nil {
		return Message{}, fmt.Errorf("thrift binary: read message header: %w", err)
	}

	var method string
	var messageType MessageType
	var sequenceID int32
	versioned := uint32(first)&0xffff0000 == 0x80010000
	if versioned {
		messageType = MessageType(uint32(first) & 0xff)
		method, err = d.readBinaryString()
		if err != nil {
			return Message{}, fmt.Errorf("thrift binary: read method name: %w", err)
		}
		sequenceID, err = d.readI32()
		if err != nil {
			return Message{}, fmt.Errorf("thrift binary: read sequence id: %w", err)
		}
	} else {
		if first < 0 || int(first) > limits.MaxBinaryBytes {
			return Message{}, fmt.Errorf("thrift binary: invalid legacy method name length %d", first)
		}
		name, err := d.read(int(first))
		if err != nil {
			return Message{}, fmt.Errorf("thrift binary: read method name: %w", err)
		}
		if !utf8.Valid(name) {
			return Message{}, fmt.Errorf("thrift binary: method name is not valid UTF-8")
		}
		method = string(name)
		kind, err := d.readByte()
		if err != nil {
			return Message{}, fmt.Errorf("thrift binary: read message type: %w", err)
		}
		messageType = MessageType(kind)
		sequenceID, err = d.readI32()
		if err != nil {
			return Message{}, fmt.Errorf("thrift binary: read sequence id: %w", err)
		}
		d.binaryBytes += len(name)
	}
	message := Message{Method: method, Type: messageType, SequenceID: sequenceID}
	if err := validateMessage(message); err != nil {
		return Message{}, err
	}
	message.Args, err = d.readStruct(0)
	if err != nil {
		return Message{}, fmt.Errorf("thrift binary: read message args: %w", err)
	}
	if err := consumeLineJSTerminator(data, &d.offset); err != nil {
		return Message{}, err
	}
	return message, nil
}

func unmarshalCompactMessage(data []byte, limits DecodeLimits) (Message, error) {
	d := compactDecoder{data: data, limits: limits}
	protocolID, err := d.readByte()
	if err != nil {
		return Message{}, fmt.Errorf("thrift compact: read message header: %w", err)
	}
	if protocolID != 0x82 {
		return Message{}, fmt.Errorf("thrift compact: invalid protocol id 0x%02x", protocolID)
	}
	versionAndType, err := d.readByte()
	if err != nil {
		return Message{}, fmt.Errorf("thrift compact: read version and type: %w", err)
	}
	if versionAndType&0x1f != 1 {
		return Message{}, fmt.Errorf("thrift compact: unsupported version %d", versionAndType&0x1f)
	}
	messageType := MessageType(versionAndType >> 5)
	sequence, err := d.readVarint()
	if err != nil {
		return Message{}, fmt.Errorf("thrift compact: read sequence id: %w", err)
	}
	if sequence > math.MaxUint32 {
		return Message{}, fmt.Errorf("thrift compact: sequence id overflows i32")
	}
	nameLength, err := d.readVarint()
	if err != nil {
		return Message{}, fmt.Errorf("thrift compact: read method name length: %w", err)
	}
	if nameLength > math.MaxUint8 {
		return Message{}, fmt.Errorf("thrift compact: method name is %d bytes; maximum is 255", nameLength)
	}
	if nameLength > uint64(limits.MaxBinaryBytes) {
		return Message{}, fmt.Errorf("thrift compact: method name exceeds binary limit %d", limits.MaxBinaryBytes)
	}
	name, err := d.read(int(nameLength))
	if err != nil {
		return Message{}, fmt.Errorf("thrift compact: read method name: %w", err)
	}
	if !utf8.Valid(name) {
		return Message{}, fmt.Errorf("thrift compact: method name is not valid UTF-8")
	}
	d.binaryBytes += len(name)
	message := Message{
		Method:     string(name),
		Type:       messageType,
		SequenceID: int32(uint32(sequence)),
	}
	if err := validateMessage(message); err != nil {
		return Message{}, err
	}
	message.Args, err = d.readStruct(0)
	if err != nil {
		return Message{}, fmt.Errorf("thrift compact: read message args: %w", err)
	}
	if err := consumeLineJSTerminator(data, &d.offset); err != nil {
		return Message{}, err
	}
	return message, nil
}

func (d *binaryDecoder) readBinaryString() (string, error) {
	size, err := d.readI32()
	if err != nil {
		return "", err
	}
	if size < 0 {
		return "", fmt.Errorf("negative string length %d", size)
	}
	if int(size) > d.limits.MaxBinaryBytes-d.binaryBytes {
		return "", fmt.Errorf("string payload exceeds aggregate limit %d", d.limits.MaxBinaryBytes)
	}
	value, err := d.read(int(size))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(value) {
		return "", fmt.Errorf("string is not valid UTF-8")
	}
	d.binaryBytes += int(size)
	return string(value), nil
}

func consumeLineJSTerminator(data []byte, offset *int) error {
	remaining := data[*offset:]
	if len(remaining) == 1 && remaining[0] == 0 {
		*offset++
		return nil
	}
	if len(remaining) != 0 {
		return fmt.Errorf("thrift: %d trailing bytes", len(remaining))
	}
	return nil
}

func validateMessage(message Message) error {
	if !utf8.ValidString(message.Method) {
		return fmt.Errorf("thrift: method name is not valid UTF-8")
	}
	if message.Type < MessageCall || message.Type > MessageOneway {
		return fmt.Errorf("thrift: invalid message type %d", message.Type)
	}
	return nil
}

func appendUnsignedVarint(data []byte, value uint64) []byte {
	for value >= 0x80 {
		data = append(data, byte(value)|0x80)
		value >>= 7
	}
	return append(data, byte(value))
}
