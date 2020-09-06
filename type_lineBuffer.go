package main

import (
	"fmt"
	"strings"
	"sync"
)

// lineBuffer stores multiple logLines in a thread-safe way.
type lineBuffer struct {
	mutex sync.Mutex
	lines []logLine
}

// Push stores a new logLine in the lineBuffer.
func (lb *lineBuffer) Push(line logLine) error {
	lb.mutex.Lock()
	lb.lines = append(lb.lines, line)
	lb.mutex.Unlock()
	return nil
}

// Pop retrieves an element of the lineBuffer.
func (lb *lineBuffer) Pop() (logLine, error) {
	lb.mutex.Lock()
	n := len(lb.lines) - 1
	if n < 0 {
		lb.mutex.Unlock()
		return logLine{}, fmt.Errorf("no elements in buffer")
	}
	line := lb.lines[n]
	lb.lines[n] = logLine{}
	lb.lines = lb.lines[:n]
	lb.mutex.Unlock()
	return line, nil
}

// Len returns the number of elements in the lineBuffer.
func (lb *lineBuffer) Len() uint32 {
	lb.mutex.Lock()
	n := len(lb.lines)
	lb.mutex.Unlock()
	return uint32(n)
}

// String returns a newline-terminated string containing all lines in the buffer.
func (lb *lineBuffer) String() string {
	var lines []string
	lb.mutex.Lock()
	for _, logLine := range lb.lines {
		lines = append(lines, logLine.String())
	}
	lb.mutex.Unlock()
	return strings.Join(lines, "\n")
}
