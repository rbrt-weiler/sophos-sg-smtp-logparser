package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"strings"
)

// parseLogLineSlice parses a slice of single log lines.
func parseLogLineSlice(threadMgmt *chan bool, lines []logLine) {
	var mails []singleMail

	for _, singleLine := range lines {
		var mail singleMail
		line := singleLine.String()
		dateTime := reDateTime.FindStringSubmatch(line)
		mail.SetDate(strings.ReplaceAll(dateTime[1], `:`, `-`))
		mail.SetTime(dateTime[2])
		from := reFrom.FindStringSubmatch(line)
		if len(from) != 2 {
			stdErr.Printf("Skipping mail: Line could not be parsed: Empty <from>\n")
			<-*threadMgmt
			return
		} else if !isValidEmail(from[1]) {
			stdErr.Printf("Skipping mail: Line could not be parsed: from <%s> is not an e-mail address\n", from[1])
			<-*threadMgmt
			return
		}
		mail.SetFrom(from[1])
		to := reTo.FindStringSubmatch(line)
		if len(to) != 2 {
			stdErr.Printf("Skipping mail: Line could not be parsed: Empty <to>\n")
			<-*threadMgmt
			return
		} else if !isValidEmail(to[1]) {
			stdErr.Printf("Skipping mail: Line could not be parsed: to <%s> is not an e-mail address\n", to[1])
			<-*threadMgmt
			return
		}
		mail.SetTo(to[1])
		subject := reSubject.FindStringSubmatch(line)
		if len(subject) != 2 {
			stdErr.Printf("Skipping mail: Line could not be parsed: Subject missing\n")
			<-*threadMgmt
			return
		}
		mail.SetSubject(subject[1])
		mail.SetSize(reSize.FindStringSubmatch(line)[1])
		mail.SetQueueID(reQueueID.FindStringSubmatch(line)[1])
		mail.GenerateMailID()
		mails = append(mails, mail)
	}

	mb.PushSlice(mails)
	<-*threadMgmt
}

// parseLogFile goes through a logfile and applies parseLogLine for relevant lines.
func parseLogFile(logfile string) error {
	var fileScanner *bufio.Scanner
	var lineNo uint32
	var lines []logLine

	file, fileErr := os.Open(logfile)
	if fileErr != nil {
		return fmt.Errorf("Failed to open file: %s", fileErr)
	}
	defer file.Close()

	if strings.HasSuffix(logfile, ".gz") {
		gz, gzErr := gzip.NewReader(file)
		if gzErr != nil {
			return fmt.Errorf("Failed to open gzip'ed file: %s", fileErr)
		}
		fileScanner = bufio.NewScanner(gz)
	} else {
		fileScanner = bufio.NewScanner(file)
	}

	lineNo = 0
	for fileScanner.Scan() {
		lineNo++
		line := fileScanner.Text()
		if !strings.Contains(line, `smtpd[`) {
			continue
		}
		if !strings.Contains(line, `name="email passed"`) {
			continue
		}
		if !strings.Contains(line, `id="1000"`) {
			continue
		}
		lines = append(lines, logLine{FileName: logfile, LineNumber: lineNo, Content: line})
	}

	pushErr := lb.PushSlice(lines)
	if pushErr != nil {
		return fmt.Errorf("Could not push slice to buffer: %s", pushErr)
	}

	return nil
}
