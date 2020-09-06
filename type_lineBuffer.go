package main

import (
	"fmt"
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

// PushSlice stores a number of new logLines in the lineBuffer.
func (lb *lineBuffer) PushSlice(lines []logLine) error {
	lb.mutex.Lock()
	for _, line := range lines {
		lb.lines = append(lb.lines, line)
	}
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
