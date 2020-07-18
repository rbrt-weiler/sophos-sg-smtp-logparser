package main

import (
	"strings"
)

// Helper type.
type stringArray []string

// Returns a comma-concatenated representation of all elements.
func (oa *stringArray) String() string {
	return strings.Join(*oa, ",")
}

// Appends a new element.
func (oa *stringArray) Set(value string) error {
	*oa = append(*oa, value)
	return nil
}

// Returns the type of the element.
func (oa *stringArray) Type() string {
	return "string"
}
