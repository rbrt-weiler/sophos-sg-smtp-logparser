package main

// logLine represents a single line of a logfile.
type logLine struct {
	FileName   string
	LineNumber uint32
	Content    string
}

// File returns the name of the file where the logLine was found.
func (ll *logLine) File() string {
	return ll.FileName
}

// Line returns the line number where the logLine was found.
func (ll *logLine) Line() uint32 {
	return ll.LineNumber
}

// String returns the content of the logLine.
func (ll logLine) String() string {
	return ll.Content
}
