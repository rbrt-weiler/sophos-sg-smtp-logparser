package main

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

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
