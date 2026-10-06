// Package thrift provides the public Thrift protocol surface used by LINEJS.
// The protocol implementations stay in the internal package so service code
// can share them without exposing the implementation layout.
package thrift

import (
	"fmt"

	protocol "github.com/phongsathornpt/line-go/internal/protocol/thrift"
)

// Type is a Thrift field or collection element type.
type Type = protocol.Type

const (
	TypeStop   = protocol.TypeStop
	TypeVoid   = protocol.TypeVoid
	TypeBool   = protocol.TypeBool
	TypeByte   = protocol.TypeByte
	TypeDouble = protocol.TypeDouble
	TypeI16    = protocol.TypeI16
	TypeI32    = protocol.TypeI32
	TypeI64    = protocol.TypeI64
	TypeString = protocol.TypeString
	TypeStruct = protocol.TypeStruct
	TypeMap    = protocol.TypeMap
	TypeSet    = protocol.TypeSet
	TypeList   = protocol.TypeList
)

// Value is a value supported by the Compact and Binary Protocol codecs.
type Value = protocol.Value

type BoolValue = protocol.BoolValue
type ByteValue = protocol.ByteValue
type I16Value = protocol.I16Value
type I32Value = protocol.I32Value
type I64Value = protocol.I64Value
type DoubleValue = protocol.DoubleValue
type StringValue = protocol.StringValue
type BinaryValue = protocol.BinaryValue
type Field = protocol.Field
type StructValue = protocol.StructValue
type ListValue = protocol.ListValue
type SetValue = protocol.SetValue
type MapEntry = protocol.MapEntry
type MapValue = protocol.MapValue
type DecodeLimits = protocol.DecodeLimits

// Protocol selects the wire encoding used by a Thrift message.
type Protocol = protocol.Protocol

type MessageType = protocol.MessageType

type Message = protocol.Message

const (
	MessageUnknown   = protocol.MessageUnknown
	MessageCall      = protocol.MessageCall
	MessageReply     = protocol.MessageReply
	MessageException = protocol.MessageException
	MessageOneway    = protocol.MessageOneway
)

// UnsupportedProtocolError reports a protocol selector outside this package's
// supported LINEJS-compatible encodings.
type UnsupportedProtocolError struct {
	Protocol Protocol
}

func (e *UnsupportedProtocolError) Error() string {
	return fmt.Sprintf("thrift: unsupported protocol %d", e.Protocol)
}

const (
	ProtocolBinary  = protocol.ProtocolBinary
	ProtocolCompact = protocol.ProtocolCompact
)

// MarshalStruct encodes a struct without a message envelope.
func MarshalStruct(protocolType Protocol, value StructValue) ([]byte, error) {
	switch protocolType {
	case ProtocolBinary:
		return protocol.MarshalBinaryStruct(value)
	case ProtocolCompact:
		return protocol.MarshalCompactStruct(value)
	default:
		return nil, errUnsupportedProtocol(protocolType)
	}
}

// UnmarshalStruct decodes one struct without a message envelope.
func UnmarshalStruct(protocolType Protocol, data []byte) (StructValue, error) {
	switch protocolType {
	case ProtocolBinary:
		return protocol.UnmarshalBinaryStruct(data)
	case ProtocolCompact:
		return protocol.UnmarshalCompactStruct(data)
	default:
		return nil, errUnsupportedProtocol(protocolType)
	}
}

// UnmarshalStructWithLimits decodes a struct with explicit resource limits.
func UnmarshalStructWithLimits(protocolType Protocol, data []byte, limits DecodeLimits) (StructValue, error) {
	switch protocolType {
	case ProtocolBinary:
		return protocol.UnmarshalBinaryStructWithLimits(data, limits)
	case ProtocolCompact:
		return protocol.UnmarshalCompactStructWithLimits(data, limits)
	default:
		return nil, errUnsupportedProtocol(protocolType)
	}
}

// MarshalRequest writes a LINEJS-style request header and Thrift args struct.
func MarshalRequest(protocolType Protocol, method string, args StructValue) ([]byte, error) {
	switch protocolType {
	case ProtocolBinary:
		return protocol.MarshalBinaryRequest(method, args)
	case ProtocolCompact:
		return protocol.MarshalCompactRequest(method, args)
	default:
		return nil, errUnsupportedProtocol(protocolType)
	}
}

// MarshalMessage encodes a Thrift message without LINEJS's request terminator.
func MarshalMessage(protocolType Protocol, message Message) ([]byte, error) {
	return protocol.MarshalMessage(protocolType, message)
}

// UnmarshalMessage decodes one Thrift message, accepting LINEJS's optional
// trailing zero request terminator.
func UnmarshalMessage(protocolType Protocol, data []byte) (Message, error) {
	return protocol.UnmarshalMessage(protocolType, data)
}

// UnmarshalMessageWithLimits decodes one message with resource limits.
func UnmarshalMessageWithLimits(protocolType Protocol, data []byte, limits DecodeLimits) (Message, error) {
	return protocol.UnmarshalMessageWithLimits(protocolType, data, limits)
}

// MarshalCompactStruct encodes one compact struct without a message envelope.
func MarshalCompactStruct(value StructValue) ([]byte, error) {
	return protocol.MarshalCompactStruct(value)
}

// MarshalCompactRequest encodes a LINE v4 compact request.
func MarshalCompactRequest(method string, args StructValue) ([]byte, error) {
	return protocol.MarshalCompactRequest(method, args)
}

// UnmarshalCompactStruct decodes one compact struct without a message envelope.
func UnmarshalCompactStruct(data []byte) (StructValue, error) {
	return protocol.UnmarshalCompactStruct(data)
}

// UnmarshalCompactStructWithLimits decodes a compact struct with resource limits.
func UnmarshalCompactStructWithLimits(data []byte, limits DecodeLimits) (StructValue, error) {
	return protocol.UnmarshalCompactStructWithLimits(data, limits)
}

// UnmarshalTMoreCompactStruct decodes LINE's compressed compact response
// structs used by the push service.
func UnmarshalTMoreCompactStruct(data []byte) (StructValue, error) {
	return protocol.UnmarshalTMoreCompactStruct(data)
}

// UnmarshalTMoreCompactStructWithLimits decodes TMoreCompact data using
// caller-selected recursion, item, and binary-size limits.
func UnmarshalTMoreCompactStructWithLimits(data []byte, limits DecodeLimits) (StructValue, error) {
	return protocol.UnmarshalTMoreCompactStructWithLimits(data, limits)
}

// MarshalBinaryStruct encodes one binary struct without a message envelope.
func MarshalBinaryStruct(value StructValue) ([]byte, error) {
	return protocol.MarshalBinaryStruct(value)
}

// MarshalBinaryRequest encodes a LINEJS-style binary request.
func MarshalBinaryRequest(method string, args StructValue) ([]byte, error) {
	return protocol.MarshalBinaryRequest(method, args)
}

// UnmarshalBinaryStruct decodes one binary struct without a message envelope.
func UnmarshalBinaryStruct(data []byte) (StructValue, error) {
	return protocol.UnmarshalBinaryStruct(data)
}

// UnmarshalBinaryStructWithLimits decodes a binary struct with resource limits.
func UnmarshalBinaryStructWithLimits(data []byte, limits DecodeLimits) (StructValue, error) {
	return protocol.UnmarshalBinaryStructWithLimits(data, limits)
}

func errUnsupportedProtocol(protocolType Protocol) error {
	return &UnsupportedProtocolError{Protocol: protocolType}
}
