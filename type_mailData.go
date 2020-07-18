package main

// Stores an indexed array of mailPartner objects.
type mailData struct {
	Partner map[string]mailPartner `json:"partners"`
}

// Append adds a singleMail object to the matching mailPartner object.
// If the mailPartner structure does not exist, Append will initialize it.
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
