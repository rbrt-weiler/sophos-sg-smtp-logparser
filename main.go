package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
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
	toolName    string = "Sophos SMTP Logparser"
	toolVersion string = "1.1.0"
	toolID      string = toolName + "/" + toolVersion
	toolURL     string = "https://gitlab.com/rbrt-weiler/sophos-smtp-logparser"
)

const (
	errSuccess    int = 0  // No error
	errUsage      int = 1  // Usage error
	errFileCreate int = 10 // Outfile could not be created
	errFileWrite  int = 11 // Outfile could not be written to
	errFileFlush  int = 13 // Outfile could not be synced to disk
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
	LogFiles      stringArray
	InternalHosts stringArray
	NoCSVHeader   bool
	JSONOutput    bool
	OutfileName   string
	PrintVersion  bool
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
	config appConfig // Holds config as defined by CLI arguments.
	mails  mailData  // Data structure for storing parsed results.

	stdOut = log.New(os.Stdout, "", log.LstdFlags) // Shortcut for CLI output.
	stdErr = log.New(os.Stderr, "", log.LstdFlags) // Shortcut for CLI output.

	// Regular expressions used for parsing a single log line.
	reDateTime = regexp.MustCompile(`^(.+?)-(.+?)\s`)
	reFrom     = regexp.MustCompile(`\sfrom="(.*?)"\s?`)
	reTo       = regexp.MustCompile(`\sto="(.*?)"\s?`)
	reSubject  = regexp.MustCompile(`\ssubject="(.*?)"\s?`)
	reSize     = regexp.MustCompile(`\ssize="(.+?)"\s?`)
	reQueueID  = regexp.MustCompile(`\squeueid="(.+?)"\s?`)
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
	pflag.VarP(&config.InternalHosts, "internalhost", "i", "Host part to be considered as internal")
	pflag.BoolVar(&config.NoCSVHeader, "no-csv-header", false, "Omit CSV header line")
	pflag.BoolVarP(&config.JSONOutput, "json", "J", false, "Output in JSON format")
	pflag.StringVarP(&config.OutfileName, "outfile", "o", "", "File to write data to instead of stdout")
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

// parseLogLine parses a single log line into a singleMail structure.
func parseLogLine(line string) (singleMail, error) {
	var mail singleMail

	dateTime := reDateTime.FindStringSubmatch(line)
	mail.SetDate(strings.ReplaceAll(dateTime[1], `:`, `-`))
	mail.SetTime(dateTime[2])
	from := reFrom.FindStringSubmatch(line)
	if len(from) != 2 {
		return mail, fmt.Errorf("Line could not be parsed: Empty <from>")
	} else if !strings.Contains(from[1], "@") {
		return mail, fmt.Errorf("Line could not be parsed: from <%s> is not an e-mail address", from[1])
	}
	mail.SetFrom(from[1])
	to := reTo.FindStringSubmatch(line)
	if len(to) != 2 {
		return mail, fmt.Errorf("Line could not be parsed: Empty <to>")
	} else if !strings.Contains(to[1], "@") {
		return mail, fmt.Errorf("Line could not be parsed: to <%s> is not an e-mail address", to[1])
	}
	mail.SetTo(to[1])
	subject := reSubject.FindStringSubmatch(line)
	if len(subject) != 2 {
		return mail, fmt.Errorf("Line could not be parsed: Subject missing")
	}
	mail.SetSubject(subject[1])
	mail.SetSize(reSize.FindStringSubmatch(line)[1])
	mail.SetQueueID(reQueueID.FindStringSubmatch(line)[1])
	mail.GenerateMailID()

	return mail, nil
}

// parseLogFile goes through a logfile and applies parseLogLine for relevant lines.
func parseLogFile(logfile string) error {
	var fileScanner *bufio.Scanner

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

	for fileScanner.Scan() {
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
		mail, mailErr := parseLogLine(line)
		if mailErr != nil {
			stdErr.Printf("Skipping mail: %s", mailErr)
			continue
		}
		mails.Append(mail)
	}

	return nil
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
	parseCLIOptions()

	if config.PrintVersion {
		fmt.Println(toolID)
		os.Exit(errSuccess)
	}

	if len(config.LogFiles) == 0 {
		stdErr.Fatal("At least one logfile is required.")
	}

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
		fileHandle, fileErr := os.Create(config.OutfileName)
		if fileErr != nil {
			stdErr.Printf("Could not create outfile: %s\n", fileErr)
			os.Exit(errFileCreate)
		}
		defer fileHandle.Close()
		fileWriter := bufio.NewWriter(fileHandle)
		_, writeErr := fileWriter.WriteString(output)
		if writeErr != nil {
			stdErr.Printf("Could not write to outfile: %s\n", writeErr)
			os.Exit(errFileWrite)
		}
		flushErr := fileWriter.Flush()
		if flushErr != nil {
			stdErr.Printf("Could not flush file buffer: %s\n", flushErr)
			os.Exit(errFileFlush)
		}
	} else {
		fmt.Print(output)
	}

	os.Exit(errSuccess)
}
