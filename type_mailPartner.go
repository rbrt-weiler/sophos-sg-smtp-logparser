package main

import (
	"fmt"
	"strings"
)

// Stores all mails belonging to a conversation alogn with statistics for that conversation.
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

// Init initializes the statistical fields of a mailPartner obejct.
func (mp *mailPartner) Init(mail singleMail) {
	partnerIndex := mail.GetPartnerKey()
	commPartners := strings.Split(partnerIndex, " ")
	mp.PartnerA = commPartners[0]
	mp.PartnerB = commPartners[1]
	mp.UserA, mp.HostA = mp.SplitAddress(mp.PartnerA)
	mp.UserB, mp.HostB = mp.SplitAddress(mp.PartnerB)
	mp.TypeA = mail.GetHostType(mp.HostA)
	mp.TypeB = mail.GetHostType(mp.HostB)
	mp.Type = fmt.Sprintf("%c2%c", mp.TypeA[0], mp.TypeB[0])
	mp.MailsTotal = 0
	mp.MailsAtoB = 0
	mp.MailsBtoA = 0
	mp.SizeTotal = 0
	mp.SizeAtoB = 0
	mp.SizeBtoA = 0
}

// SplitAddress splits up the given email address into user and host parts.
func (mp *mailPartner) SplitAddress(email string) (string, string) {
	parts := strings.Split(email, "@")
	return parts[0], parts[1]
}

// IsFromA returns true if the given singleMail object is from PartnerA, else false.
func (mp *mailPartner) IsFromA(mail singleMail) bool {
	return (mp.PartnerA == mail.From)
}

// IsFromB returns true if the given singleMail object is from PartnerB, else false.
func (mp *mailPartner) IsFromB(mail singleMail) bool {
	return !mp.IsFromA(mail)
}

// AddMail stores a singleMail in the mailPartner structure and updates the statistics accordingly.
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

// ToCSV returns a CSV representation of a mailPartner object.
func (mp *mailPartner) ToCSV() string {
	return fmt.Sprintf(csvFormat, mp.Type, mp.SizeAtoB, mp.MailsAtoB, mp.PartnerA, mp.PartnerB, mp.MailsBtoA, mp.SizeBtoA)
}
