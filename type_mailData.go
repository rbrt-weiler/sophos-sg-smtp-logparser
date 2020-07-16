package main

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
