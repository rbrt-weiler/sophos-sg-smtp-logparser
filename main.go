package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	pflag "github.com/spf13/pflag"
)

/*
 ######   #######  ##    ##  ######  ########    ###    ##    ## ########  ######
##    ## ##     ## ###   ## ##    ##    ##      ## ##   ###   ##    ##    ##    ##
##       ##     ## ####  ## ##          ##     ##   ##  ####  ##    ##    ##
##       ##     ## ## ## ##  ######     ##    ##     ## ## ## ##    ##     ######
##       ##     ## ##  ####       ##    ##    ######### ##  ####    ##          ##
##    ## ##     ## ##   ### ##    ##    ##    ##     ## ##   ###    ##    ##    ##
 ######   #######  ##    ##  ######     ##    ##     ## ##    ##    ##     ######
*/

const (
	toolName    string = "Sophos SG SMTP Logfile Parser"
	toolVersion string = "1.3.1-multithread"
	toolID      string = toolName + "/" + toolVersion
	toolURL     string = "https://gitlab.com/rbrt-weiler/sophos-sg-smtp-logparser"
)

const (
	errSuccess    int = 0  // No error
	errUsage      int = 1  // Usage error
	errFileCreate int = 10 // Outfile could not be created
	errFileWrite  int = 11 // Outfile could not be written to
	errFileFlush  int = 12 // Outfile could not be synced to disk
	errGzipCreate int = 20 // Gzip stream could not be created
	errGzipWrite  int = 21 // Gzip stream could not be written to
	errGzipFlush  int = 22 // Gzip stream could not be synced
	errGzipClose  int = 23 // Gzip stream could not be closed
)

/*
 ######   #######  ##    ## ######## ####  ######
##    ## ##     ## ###   ## ##        ##  ##    ##
##       ##     ## ####  ## ##        ##  ##
##       ##     ## ## ## ## ######    ##  ##   ####
##       ##     ## ##  #### ##        ##  ##    ##
##    ## ##     ## ##   ### ##        ##  ##    ##
 ######   #######  ##    ## ##       ####  ######
*/

// appConfig defines a storage type for global app configuration.
type appConfig struct {
	SpareThreads   int
	LogFiles       stringArray
	InternalHosts  stringArray
	NoCSVHeader    bool
	JSONOutput     bool
	OutfileName    string
	CompressOutput bool
	PrintVersion   bool
}

/*
 ######   ##        #######  ########     ###    ##          ##     ##    ###    ########   ######
##    ##  ##       ##     ## ##     ##   ## ##   ##          ##     ##   ## ##   ##     ## ##    ##
##        ##       ##     ## ##     ##  ##   ##  ##          ##     ##  ##   ##  ##     ## ##
##   #### ##       ##     ## ########  ##     ## ##          ##     ## ##     ## ########   ######
##    ##  ##       ##     ## ##     ## ######### ##           ##   ##  ######### ##   ##         ##
##    ##  ##       ##     ## ##     ## ##     ## ##            ## ##   ##     ## ##    ##  ##    ##
 ######   ########  #######  ########  ##     ## ########       ###    ##     ## ##     ##  ######
*/

var (
	config appConfig  // Holds config as defined by CLI arguments.
	lb     lineBuffer // Stores log lines that should be parsed
	mb     mailBuffer // Temporary storage for parsed mails
	mails  mailData   // Data structure for storing parsed results.

	stdOut = log.New(os.Stdout, "", log.LstdFlags) // Shortcut for CLI output.
	stdErr = log.New(os.Stderr, "", log.LstdFlags) // Shortcut for CLI output.

	// Regular expressions used for parsing a single log line.
	reDateTime   = regexp.MustCompile(`^(.+?)-(.+?)\s`)
	reValidEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	reFrom       = regexp.MustCompile(`\sfrom="(.*?)"\s?`)
	reTo         = regexp.MustCompile(`\sto="(.*?)"\s?`)
	reSubject    = regexp.MustCompile(`\ssubject="(.*?)"\s?`)
	reSize       = regexp.MustCompile(`\ssize="(.+?)"\s?`)
	reQueueID    = regexp.MustCompile(`\squeueid="(.+?)"\s?`)
)

/*
 #######  ########  ######## ####  #######  ##    ##    ########     ###    ########   ######  #### ##    ##  ######
##     ## ##     ##    ##     ##  ##     ## ###   ##    ##     ##   ## ##   ##     ## ##    ##  ##  ###   ## ##    ##
##     ## ##     ##    ##     ##  ##     ## ####  ##    ##     ##  ##   ##  ##     ## ##        ##  ####  ## ##
##     ## ########     ##     ##  ##     ## ## ## ##    ########  ##     ## ########   ######   ##  ## ## ## ##   ####
##     ## ##           ##     ##  ##     ## ##  ####    ##        ######### ##   ##         ##  ##  ##  #### ##    ##
##     ## ##           ##     ##  ##     ## ##   ###    ##        ##     ## ##    ##  ##    ##  ##  ##   ### ##    ##
 #######  ##           ##    ####  #######  ##    ##    ##        ##     ## ##     ##  ######  #### ##    ##  ######
*/

// parseCLIOptions parses the provided CLI arguments into appConfig.
func parseCLIOptions() {
	pflag.IntVar(&config.SpareThreads, "sparethreads", 2, "Threads to keep free for other programs")
	pflag.VarP(&config.InternalHosts, "internalhost", "i", "Host part to be considered as internal")
	pflag.BoolVar(&config.NoCSVHeader, "no-csv-header", false, "Omit CSV header line")
	pflag.BoolVarP(&config.JSONOutput, "json", "J", false, "Output in JSON format")
	pflag.StringVarP(&config.OutfileName, "outfile", "o", "", "File to write data to instead of stdout")
	pflag.BoolVarP(&config.CompressOutput, "compress-outfile", "Z", false, "Compress output (with -o)")
	pflag.BoolVar(&config.PrintVersion, "version", false, "Print version information and exit")
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n", toolID)
		fmt.Fprintf(os.Stderr, "%s\n", toolURL)
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "This tool parses a number of Sophos SG SMTP logfiles (uncompressed and\n")
		fmt.Fprintf(os.Stderr, "gzip'ed) and provides an overview of the e-mails sent and received. It\n")
		fmt.Fprintf(os.Stderr, "supports two output formats:\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "CSV (the default) provides a CSV-styled list of communication partners\n")
		fmt.Fprintf(os.Stderr, "and their associated mail volume (count and bytes). It is intended to\n")
		fmt.Fprintf(os.Stderr, "give administrators a quick overview of the mail traffic.\n")
		fmt.Fprintf(os.Stderr, "JSON provides a very detailed representation of the e-mails sent between\n")
		fmt.Fprintf(os.Stderr, "communication partners. It is intended to be used by another program.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Regular output is printed to stdout, everything else is printed to stderr.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options] logfile...\n", path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Available options:\n")
		pflag.PrintDefaults()
		os.Exit(errUsage)
	}
	pflag.Parse()
	config.LogFiles = pflag.Args()
}

/*
######## ##     ## ##    ##  ######  ######## ####  #######  ##    ##  ######
##       ##     ## ###   ## ##    ##    ##     ##  ##     ## ###   ## ##    ##
##       ##     ## ####  ## ##          ##     ##  ##     ## ####  ## ##
######   ##     ## ## ## ## ##          ##     ##  ##     ## ## ## ##  ######
##       ##     ## ##  #### ##          ##     ##  ##     ## ##  ####       ##
##       ##     ## ##   ### ##    ##    ##     ##  ##     ## ##   ### ##    ##
##        #######  ##    ##  ######     ##    ####  #######  ##    ##  ######
*/

// isValidEmail returns true if address is a valid e-mail address, else false.
func isValidEmail(address string) bool {
	return reValidEmail.MatchString(address)
}

// parseLogLine parses a single log line into a singleMail structure.
func parseLogLine(threadMgmt *chan bool, line string) {
	var mail singleMail

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

	mb.Push(mail)
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

// waitAndClear completely fills and clears the thread management semaphore.
func waitAndClear(threadMgmt *chan bool) {
	for i := 0; i < cap(*threadMgmt); i++ {
		*threadMgmt <- true
	}
	for i := 0; i < cap(*threadMgmt); i++ {
		<-*threadMgmt
	}
}

/*
##     ##    ###    #### ##    ##
###   ###   ## ##    ##  ###   ##
#### ####  ##   ##   ##  ####  ##
## ### ## ##     ##  ##  ## ## ##
##     ## #########  ##  ##  ####
##     ## ##     ##  ##  ##   ###
##     ## ##     ## #### ##    ##
*/

func main() {
	var numCPUs int
	var maxThreads int
	var i uint32

	parseCLIOptions()

	if config.PrintVersion {
		fmt.Println(toolID)
		os.Exit(errSuccess)
	}

	if len(config.LogFiles) == 0 {
		stdErr.Fatal("At least one logfile is required.")
	}

	numCPUs = runtime.NumCPU()
	maxThreads = numCPUs - config.SpareThreads
	if maxThreads > numCPUs {
		maxThreads = numCPUs
	}
	if maxThreads < 2 {
		maxThreads = 2
	}
	threadManager := make(chan bool, maxThreads-1)

	mails.CreateDateTime = time.Now()
	mails.CreateDateTimeUnix = mails.CreateDateTime.Unix()
	mails.CreateDate = mails.CreateDateTime.Format("2006-01-02")
	mails.CreateTime = mails.CreateDateTime.Format("15:04:05")

	for _, logfile := range config.LogFiles {
		parseErr := parseLogFile(logfile)
		if parseErr != nil {
			stdOut.Println(parseErr)
		}
	}

	if lb.Len() > 0 {
		elements := lb.Len()
		for i = 0; i < elements; i++ {
			line, lineErr := lb.Pop()
			if lineErr != nil {
				stdErr.Printf("Could not pop log line: %s\n", lineErr)
				continue
			}
			threadManager <- true
			go parseLogLine(&threadManager, line.String())
		}
	} else {
		stdErr.Println("No relevant log lines found. Exiting.")
		os.Exit(errSuccess)
	}
	waitAndClear(&threadManager)

	if mb.Len() > 0 {
		elements := mb.Len()
		for i = 0; i < elements; i++ {
			mail, mailErr := mb.Pop()
			if mailErr != nil {
				stdErr.Printf("Could not pop mail: %s\n", mailErr)
				continue
			}
			mails.Append(mail)
		}
	} else {
		stdErr.Println("No parsable log line found. Exiting.")
		os.Exit(errSuccess)
	}

	output := ""
	if config.JSONOutput {
		json, _ := json.MarshalIndent(mails, "", "    ")
		output = string(json)
	} else {
		if !config.NoCSVHeader {
			output = fmt.Sprintf("%s%s\n", output, mailPartnerCSVHeader)
		}
		var keys []string
		for k := range mails.Partner {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			mp := mails.Partner[k]
			output = fmt.Sprintf("%s%s\n", output, mp.ToCSV())
		}
	}
	output = strings.TrimSpace(output)

	if config.OutfileName != "" {
		var errCode int
		var outErr error
		if config.CompressOutput {
			errCode, outErr = writeCompressedOutfile(config.OutfileName, output)
		} else {
			errCode, outErr = writeOutfile(config.OutfileName, output)
		}
		if outErr != nil {
			stdErr.Printf("%s\n", outErr)
			os.Exit(errCode)
		}
	} else {
		fmt.Print(output)
	}

	os.Exit(errSuccess)
}
