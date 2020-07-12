package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strconv"
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

type singleMail struct {
	MailID   string `json:"mailID"`
	QueueID  string `json:"queueID"`
	Date     string `json:"date"`
	Time     string `json:"time"`
	From     string `json:"from"`
	HostFrom string `json:"hostFrom"`
	UserFrom string `json:"userFrom"`
	TypeFrom string `json:"typeFrom"`
	To       string `json:"to"`
	HostTo   string `json:"hostTo"`
	UserTo   string `json:"userTo"`
	TypeTo   string `json:"typeTo"`
	Size     int    `json:"size"`
	Subject  string `json:"subject"`
}

func (sm *singleMail) SetDate(date string) {
	sm.Date = date
}

func (sm *singleMail) SetTime(time string) {
	sm.Time = time
}

func (sm *singleMail) SetFrom(from string) {
	sm.From = from
	fromParts := strings.Split(from, `@`)
	sm.HostFrom = fromParts[1]
	sm.UserFrom = fromParts[0]
}

func (sm *singleMail) SetTo(to string) {
	sm.To = to
	toParts := strings.Split(to, `@`)
	sm.HostTo = toParts[1]
	sm.UserTo = toParts[0]
}

func (sm *singleMail) SetSubject(subject string) {
	sm.Subject = subject
}

func (sm *singleMail) SetSize(size string) {
	mailSize, mailSizeErr := strconv.Atoi(size)
	if mailSizeErr != nil {
		sm.Size = -1
	}
	sm.Size = mailSize
}

func (sm *singleMail) SetQueueID(queueID string) {
	sm.QueueID = queueID
}

func (sm *singleMail) GenerateMailID() {
	idString := fmt.Sprintf("%s %s %s %s %s", sm.QueueID, sm.Date, sm.Time, sm.From, sm.To)
	mailID := sha256.Sum256([]byte(idString))
	sm.MailID = fmt.Sprintf("%x", mailID)
}

func (sm *singleMail) GetPartnerKey() string {
	commPartnerA := sm.From
	commPartnerB := sm.To

	if sm.HostFrom == sm.HostTo {
		if sm.From > sm.To {
			commPartnerA = sm.To
			commPartnerB = sm.From
		}
	} else if sm.HostFrom > sm.HostTo {
		commPartnerA = sm.To
		commPartnerB = sm.From
	}

	return fmt.Sprintf("%s %s", commPartnerA, commPartnerB)
}

type mailStats struct {
	MailsTotal uint `json:"mailsTotal"`
	SizeTotal  uint `json:"sizeTotal"`
	CountAtoB  uint `json:"countAtoB"`
	SizeAtoB   uint `json:"sizeAtoB"`
	CountBtoA  uint `json:"countBtoA"`
	SizeBtoA   uint `json:"sizeBtoA"`
}

func (ms *mailStats) Add(singleMail) {
	fmt.Println("Would add to statistics now.")
}

type mailData struct {
	Partner map[string][]singleMail `json:"partners"`
}

func (md *mailData) Append(mail singleMail) {
	partnerIndex := mail.GetPartnerKey()
	if _, ok := md.Partner[partnerIndex]; !ok {
		md.Partner = make(map[string][]singleMail)
	}
	md.Partner[partnerIndex] = append(md.Partner[partnerIndex], mail)
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

	reDateTime = regexp.MustCompile(`^(.+?)-(.+?)\s`)
	reFrom     = regexp.MustCompile(`\sfrom="(.+?)"\s?`)
	reTo       = regexp.MustCompile(`\sto="(.+?)"\s?`)
	reSubject  = regexp.MustCompile(`\ssubject="(.+?)"\s?`)
	reSize     = regexp.MustCompile(`\ssize="(.+?)"\s?`)
	reQueueID  = regexp.MustCompile(`\squeueid="(.+?)"\s?`)
)

func parseCLIOptions() {
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
		fmt.Fprintf(os.Stderr, "Usage: %s [options] logfile...\n", path.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Available options:\n")
		pflag.PrintDefaults()
		os.Exit(errUsage)
	}
	pflag.Parse()
	config.LogFiles = pflag.Args()
}

func parseLogLine(line string) (singleMail, error) {
	var mail singleMail

	dateTime := reDateTime.FindStringSubmatch(line)
	mail.SetDate(strings.ReplaceAll(dateTime[1], `:`, `-`))
	mail.SetTime(dateTime[2])
	mail.SetFrom(reFrom.FindStringSubmatch(line)[1])
	mail.SetTo(reTo.FindStringSubmatch(line)[1])
	mail.SetSubject(reSubject.FindStringSubmatch(line)[1])
	mail.SetSize(reSize.FindStringSubmatch(line)[1])
	mail.SetQueueID(reQueueID.FindStringSubmatch(line)[1])
	mail.GenerateMailID()

	return mail, nil
}

func parseLogFile(logfile string) error {
	file, fileErr := os.Open(logfile)
	if fileErr != nil {
		return fmt.Errorf("Failed to open file: %s", fileErr)
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
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
		parseErr := parseLogFile(logfile)
		if parseErr != nil {
			stdOut.Println(parseErr)
		}
	}

	json, _ := json.MarshalIndent(mails, "", "    ")
	fmt.Println(string(json))

	stdErr.Println("main(): Code missing.")
}
