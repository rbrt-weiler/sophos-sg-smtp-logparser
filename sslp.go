package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	pflag "github.com/spf13/pflag"
)

const (
	toolName    string = "Sophos SMTP Logparser"
	toolVersion string = "0.0.0"
	toolID      string = toolName + "/" + toolVersion
	toolURL     string = "https://gitlab.com/rbrt-weiler/sophos-smtp-logparser"
)

const (
	errSuccess int = 0 // No error
	errUsage   int = 1 // Usage error
)

type stringArray []string

// Returns a concatenated representation of all elements.
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

type mailData struct {
	Mails []struct {
		MailPartners []struct {
			MailID      string `json:"mailID"`
			QueueID     string `json:"queueID"`
			Date        string `json:"date"`
			Time        string `json:"time"`
			MailFrom    string `json:"mailFrom"`
			HostFrom    string `json:"hostFrom"`
			UserFrom    string `json:"userFrom"`
			TypeFrom    string `json:"typeFrom"`
			MailTo      string `json:"mailTo"`
			HostTo      string `json:"hostTo"`
			UserTo      string `json:"userTo"`
			TypeTo      string `json:"typeTo"`
			MailSize    int    `json:"mailSize"`
			MailSubject string `json:"mailSubject"`
		} `json:"mailPartners"`
	} `json:"mails"`
}

type appConfig struct {
	LogFiles       stringArray
	InternalHosts  stringArray
	OutFiles       stringArray
	Delimiter      string
	CompressOutput bool
	PrintVersion   bool
}

var (
	config appConfig
	mails  mailData

	stdOut = log.New(os.Stdout, "", log.LstdFlags)
	stdErr = log.New(os.Stderr, "", log.LstdFlags)
)

func parseCLIOptions() {
	pflag.VarP(&config.LogFiles, "logfile", "l", "Logfile to parse")
	pflag.VarP(&config.InternalHosts, "internalhost", "i", "Host part to be considered as internal")
	pflag.VarP(&config.OutFiles, "outfile", "o", "File to write results to")
	pflag.StringVarP(&config.Delimiter, "delimiter", "d", ",", "Delimiter to use in CSV output")
	pflag.BoolVarP(&config.CompressOutput, "compress", "C", false, "Compress output using gzip")
	pflag.BoolVar(&config.PrintVersion, "version", false, "Print version information and exit")
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n", toolID)
		fmt.Fprintf(os.Stderr, "%s\n", toolURL)
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "This tool parses a number of Sophos SMTP logfiles.\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Available options:\n")
		pflag.PrintDefaults()
		os.Exit(errUsage)
	}
	pflag.Parse()
}

func parseLogFile(logfile string) {
	stdErr.Printf(`parseLogFile("%s"): Code missing.`, logfile)
}

func main() {
	parseCLIOptions()

	if config.PrintVersion {
		fmt.Println(toolID)
		os.Exit(errSuccess)
	}

	if len(config.LogFiles) == 0 {
		stdErr.Fatal("At least one logfile is required.")
	}
	if len(config.OutFiles) == 0 {
		stdErr.Fatal("At least one outfile is required.")
	}

	for _, logfile := range config.LogFiles {
		parseLogFile(logfile)
	}

	stdErr.Println("main(): Code missing.")
}
