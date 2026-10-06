package agent

import (
	"bufio"
	"io"
	"strings"
)

type sseEvent struct {
	name string
	data string
}

type sseReader struct {
	reader *bufio.Reader
	lines  []string
	event  sseEvent
	err    error
	done   bool
}

func newSSEReader(body io.Reader) *sseReader {
	return &sseReader{reader: bufio.NewReader(body)}
}

func (s *sseReader) Next() bool {
	if s.done || s.err != nil {
		return false
	}
	for {
		line, err := s.reader.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimSuffix(line, "\n")
			line = strings.TrimSuffix(line, "\r")
			if line == "" {
				if len(s.lines) == 0 {
					if err != nil {
						s.done = true
						return false
					}
					continue
				}
				s.event = parseSSEEvent(s.lines)
				s.lines = s.lines[:0]
				return true
			}
			s.lines = append(s.lines, line)
		}
		if err != nil {
			if err != io.EOF {
				s.err = err
				return false
			}
			s.done = true
			if len(s.lines) == 0 {
				return false
			}
			s.event = parseSSEEvent(s.lines)
			s.lines = nil
			return true
		}
	}
}

func (s *sseReader) Event() sseEvent {
	return s.event
}

func (s *sseReader) Err() error {
	return s.err
}

func parseSSEEvent(lines []string) sseEvent {
	var event sseEvent
	var data []string
	for _, line := range lines {
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, found := strings.Cut(line, ":")
		if !found {
			value = ""
		}
		value = strings.TrimSpace(value)
		switch field {
		case "event":
			event.name = value
		case "data":
			data = append(data, value)
		}
	}
	event.data = strings.Join(data, "\n")
	return event
}
