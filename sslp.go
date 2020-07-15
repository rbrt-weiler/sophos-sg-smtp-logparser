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
	"sort"
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
	Size     int64  `json:"size"`
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
	sm.TypeFrom = sm.GetHostType(sm.HostFrom)
}

func (sm *singleMail) SetTo(to string) {
	sm.To = to
	toParts := strings.Split(to, `@`)
	sm.HostTo = toParts[1]
	sm.UserTo = toParts[0]
	sm.TypeTo = sm.GetHostType(sm.HostTo)
}

func (sm *singleMail) SetSubject(subject string) {
	sm.Subject = subject
}

func (sm *singleMail) SetSize(size string) {
	mailSize, mailSizeErr := strconv.Atoi(size)
	if mailSizeErr != nil {
		sm.Size = -1
	}
	sm.Size = int64(mailSize)
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

func (sm *singleMail) GetHostType(host string) string {
	if sort.SearchStrings(strings.Split(config.InternalHosts.String(), ","), host) == 0 {
		return "internal"
	}
	return "external"
}

type mailPartner struct {
	PartnerA   string       `json:"partnerA"`
	UserA      string       `json:"userA"`
	HostA      string       `json:"hostA"`
	TypeA      string       `json:"typeA"`
	PartnerB   string       `json:"partnerB"`
	UserB      string       `json:"userB"`
	HostB      string       `json:"hostB"`
	TypeB      string       `json:"typeB"`
	Type       string       `json:"type"`
	MailsTotal int64        `json:"mailsTotal"`
	SizeTotal  int64        `json:"sizeTotal"`
	MailsAtoB  int64        `json:"mailsAtoB"`
	SizeAtoB   int64        `json:"sizeAtoB"`
	MailsBtoA  int64        `json:"mailsBtoA"`
	SizeBtoA   int64        `json:"sizeBtoA"`
	Mails      []singleMail `json:"mails"`
}

func (mp *mailPartner) Init(partnerIndex string) {
	commPartners := strings.Split(partnerIndex, " ")
	mp.PartnerA = commPartners[0]
	mp.PartnerB = commPartners[1]
	mp.UserA, mp.HostA = mp.SplitAddress(mp.PartnerA)
	mp.UserB, mp.HostB = mp.SplitAddress(mp.PartnerB)
	mp.TypeA = mp.GetHostType(mp.HostA)
	mp.TypeB = mp.GetHostType(mp.HostB)
	mp.Type = fmt.Sprintf("%c2%c", mp.TypeA[0], mp.TypeB[0])
	mp.MailsTotal = 0
	mp.MailsAtoB = 0
	mp.MailsBtoA = 0
	mp.SizeTotal = 0
	mp.SizeAtoB = 0
	mp.SizeBtoA = 0
}

func (mp *mailPartner) SplitAddress(email string) (string, string) {
	parts := strings.Split(email, "@")
	return parts[0], parts[1]
}

func (mp *mailPartner) GetHostType(host string) string {
	// TODO: Replace SearchStrings - "senderdomain.tldc" also matches "senderdomain.tld"
	if sort.SearchStrings(strings.Split(config.InternalHosts.String(), ","), host) == 0 {
		return "internal"
	}
	return "external"
}

func (mp *mailPartner) IsFromA(mail singleMail) bool {
	return (mp.PartnerA == mail.From)
}

func (mp *mailPartner) IsFromB(mail singleMail) bool {
	return !mp.IsFromA(mail)
}

func (mp *mailPartner) AddMail(mail singleMail) {
	mp.Mails = append(mp.Mails, mail)
	mp.MailsTotal++
	mp.SizeTotal = mp.SizeTotal + mail.Size
	if mp.IsFromA(mail) {
		mp.MailsAtoB++
		mp.SizeAtoB = mp.SizeAtoB + mail.Size
	} else {
		mp.MailsBtoA++
		mp.SizeBtoA = mp.SizeBtoA + mail.Size
	}
}

type mailData struct {
	Partner map[string]mailPartner `json:"partners"`
}

func (md *mailData) Append(mail singleMail) {
	partnerIndex := mail.GetPartnerKey()
	if md.Partner == nil {
		md.Partner = make(map[string]mailPartner)
	}
	partner := md.Partner[partnerIndex]
	if partner.MailsTotal < 1 {
		partner.Init(partnerIndex)
	}
	partner.AddMail(mail)
	md.Partner[partnerIndex] = partner
}

type appConfig struct {
	LogFiles      stringArray
	InternalHosts stringArray
	OutJSON       bool
	PrintVersion  bool
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
	pflag.BoolVarP(&config.OutJSON, "json", "J", false, "Output in JSON format")
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
	from := reFrom.FindStringSubmatch(line)
	if len(from) != 2 {
		return mail, fmt.Errorf("Line could not be parsed: Empty <from>")
	} else if !strings.Contains(from[1], "@") {
		return mail, fmt.Errorf("Line could not be parsed: <from> is not an e-mail address")
	}
	mail.SetFrom(from[1])
	to := reTo.FindStringSubmatch(line)
	if len(to) != 2 {
		return mail, fmt.Errorf("Line could not be parsed: Empty <to>")
	} else if !strings.Contains(to[1], "@") {
		return mail, fmt.Errorf("Line could not be parsed: <to> is not an e-mail address")
	}
	mail.SetTo(to[1])
	subject := reSubject.FindStringSubmatch(line)
	if len(subject) != 2 {
		return mail, fmt.Errorf("Line could not be parsed: Subject missing")
	} else if subject[1] == "" {
		return mail, fmt.Errorf("Line could not be parsed: Subject missing")
	}
	mail.SetSubject(subject[1])
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

	for _, logfile := range config.LogFiles {
		parseErr := parseLogFile(logfile)
		if parseErr != nil {
			stdOut.Println(parseErr)
		}
	}

	if config.OutJSON {
		json, _ := json.MarshalIndent(mails, "", "    ")
		fmt.Println(string(json))
	} else {
		csvFormat := "%s,%d,%d,%s,%s,%d,%d\n"
		fmt.Printf("type,sizeAtoB,countAtoB,partnerA,partnerB,countBtoA,sizeBtoA\n")
		for _, mp := range mails.Partner {
			fmt.Printf(csvFormat, mp.Type, mp.SizeAtoB, mp.MailsAtoB, mp.PartnerA, mp.PartnerB, mp.MailsBtoA, mp.SizeBtoA)
		}
	}
}
