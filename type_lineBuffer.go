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

// Push stores a new logLine at the end of the lineBuffer.
func (lb *lineBuffer) Push(line logLine) error {
	lb.mutex.Lock()
	lb.lines = append(lb.lines, line)
	lb.mutex.Unlock()
	return nil
}

// PushSlice stores a number of new logLines at the end of the lineBuffer.
func (lb *lineBuffer) PushSlice(lines []logLine) error {
	lb.mutex.Lock()
	for _, line := range lines {
		lb.lines = append(lb.lines, line)
	}
	lb.mutex.Unlock()
	return nil
}

// PopSlice retrieves a number of elements off the end of the lineBuffer.
func (lb *lineBuffer) PopSlice(elements int) ([]logLine, error) {
	var logLines []logLine

	if elements < 1 {
		return logLines, fmt.Errorf("need to fetch at least 1 element")
	}

	lb.mutex.Lock()
	lineCount := len(lb.lines)
	if lineCount < 1 {
		lb.mutex.Unlock()
		return logLines, fmt.Errorf("no elements in buffer")
	}
	if elements < lineCount {
		start := lineCount - elements
		logLines = lb.lines[start:]
		lb.lines = lb.lines[:start]
	} else {
		logLines = lb.lines
		lb.lines = lb.lines[:0]
	}
	lb.mutex.Unlock()
	return logLines, nil
}

// Pop retrieves an element off the end of the lineBuffer.
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
