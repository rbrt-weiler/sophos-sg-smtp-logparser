package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"time"
)

// writeOutfile writes content to fileName.
func writeOutfile(fileName string, content string) (int, error) {
	fileHandle, fileErr := os.Create(fileName)
	if fileErr != nil {
		return errFileCreate, fmt.Errorf("Could not create outfile: %s", fileErr)
	}
	defer fileHandle.Close()
	fileWriter := bufio.NewWriter(fileHandle)
	_, writeErr := fileWriter.WriteString(content)
	if writeErr != nil {
		return errFileWrite, fmt.Errorf("Could not write to outfile: %s", writeErr)
	}
	flushErr := fileWriter.Flush()
	if flushErr != nil {
		return errFileFlush, fmt.Errorf("Could not flush file buffer: %s", flushErr)
	}
	return errSuccess, nil
}

// writeCompressedOutfile writes compressed content to fileName.
func writeCompressedOutfile(fileName string, content string) (int, error) {
	var buf bytes.Buffer
	gzipWriter, gzipWriterErr := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if gzipWriterErr != nil {
		return errGzipCreate, fmt.Errorf("Could not create gzip stream: %s", gzipWriterErr)
	}
	gzipWriter.ModTime = time.Now()
	gzipWriter.Comment = fmt.Sprintf("created with %s", toolID)
	_, writeErr := gzipWriter.Write([]byte(content))
	if writeErr != nil {
		return errGzipWrite, fmt.Errorf("Could not write to gzip buffer: %s", writeErr)
	}
	flushErr := gzipWriter.Flush()
	if flushErr != nil {
		return errGzipFlush, fmt.Errorf("Could not flush gzip buffer: %s", flushErr)
	}
	closeErr := gzipWriter.Close()
	if closeErr != nil {
		return errGzipClose, fmt.Errorf("Could not close gzip stream: %s", closeErr)
	}
	return writeOutfile(fileName, buf.String())
}
