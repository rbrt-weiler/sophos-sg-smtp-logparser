package main

import (
	"fmt"
	"strings"
)

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
	for _, intHost := range config.InternalHosts {
		if intHost == host {
			return "internal"
		}
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
