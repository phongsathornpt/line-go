// Package push implements LINE's framed HTTP/2 push transport.
package push

import (
	"encoding/binary"
	"fmt"
)

// FrameType identifies a packet in the LINE push stream.
type FrameType uint8

const (
	FrameStatus     FrameType = 0
	FramePing       FrameType = 1
	FrameRequest    FrameType = 2
	FrameResponse   FrameType = 3
	FramePush       FrameType = 4
	FrameClose      FrameType = 5
	maxFramePayload           = 1<<16 - 1
)

// Frame is one decoded LINE push packet.
type Frame struct {
	Type    FrameType
	Payload []byte
}

// Encode serializes the two-byte length, frame type, and payload.
func (f Frame) Encode() ([]byte, error) {
	if len(f.Payload) > maxFramePayload {
		return nil, fmt.Errorf("line push: frame payload is %d bytes; maximum is %d", len(f.Payload), maxFramePayload)
	}
	encoded := make([]byte, 3+len(f.Payload))
	binary.BigEndian.PutUint16(encoded[:2], uint16(len(f.Payload)))
	encoded[2] = byte(f.Type)
	copy(encoded[3:], f.Payload)
	return encoded, nil
}

// DecodePing returns the ping type and ID from a Ping frame.
func (f Frame) DecodePing() (pingType uint8, pingID uint16, err error) {
	if f.Type != FramePing || len(f.Payload) != 3 {
		return 0, 0, fmt.Errorf("line push: invalid ping frame")
	}
	return f.Payload[0], binary.BigEndian.Uint16(f.Payload[1:]), nil
}

// DecodeSignOnResponse extracts the request ID, FIN flag, and response bytes.
func (f Frame) DecodeSignOnResponse() (requestID uint16, fin bool, response []byte, err error) {
	if f.Type != FrameResponse || len(f.Payload) < 2 {
		return 0, false, nil, fmt.Errorf("line push: invalid sign-on response frame")
	}
	encodedID := binary.BigEndian.Uint16(f.Payload[:2])
	return encodedID & 0x7fff, encodedID&0x8000 != 0, f.Payload[2:], nil
}

// DecodePush extracts the push type, service, push ID, and event payload.
func (f Frame) DecodePush() (pushType uint8, service uint8, pushID uint32, payload []byte, err error) {
	if f.Type != FramePush || len(f.Payload) < 6 {
		return 0, 0, 0, nil, fmt.Errorf("line push: invalid push frame")
	}
	return f.Payload[0], f.Payload[1], binary.BigEndian.Uint32(f.Payload[2:6]), f.Payload[6:], nil
}

// PingAck builds an acknowledgement packet for a ping ID.
func PingAck(pingID uint16) Frame {
	payload := make([]byte, 3)
	payload[0] = 1
	binary.BigEndian.PutUint16(payload[1:], pingID)
	return Frame{Type: FramePing, Payload: payload}
}

// PushAck builds an acknowledgement packet for a push event.
func PushAck(service uint8, pushID uint32) Frame {
	payload := make([]byte, 6)
	payload[0] = 1
	payload[1] = service
	binary.BigEndian.PutUint32(payload[2:], pushID)
	return Frame{Type: FramePush, Payload: payload}
}

// RequestFrame wraps a service payload in an outer push packet.
func RequestFrame(service uint8, payload []byte) Frame {
	return Frame{Type: FrameRequest, Payload: append([]byte{service}, payload...)}
}

// SignOnPayload encodes the LINE request-ID/service header carried inside a
// request packet. The Thrift request is supplied as payload.
func SignOnPayload(requestID uint16, service uint8, payload []byte) ([]byte, error) {
	if len(payload) > maxFramePayload-6 {
		return nil, fmt.Errorf("line push: sign-on payload is %d bytes; maximum is %d", len(payload), maxFramePayload-6)
	}
	encoded := make([]byte, 6+len(payload))
	binary.BigEndian.PutUint16(encoded[:2], requestID&0x7fff)
	encoded[2] = service
	encoded[3] = 0
	binary.BigEndian.PutUint16(encoded[4:6], uint16(len(payload)))
	copy(encoded[6:], payload)
	return encoded, nil
}

// ServiceMask returns the bit mask used by LINE's /PUSH subscription URL.
func ServiceMask(services []uint8) (uint32, error) {
	var mask uint32
	for _, service := range services {
		if service == 0 || service > 32 {
			return 0, fmt.Errorf("line push: service ID %d is outside the mask range 1..32", service)
		}
		mask |= uint32(1) << (service - 1)
	}
	return mask, nil
}
