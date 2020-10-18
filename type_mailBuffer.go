package main

import (
	"fmt"
	"sync"
)

// mailBuffer stores multiple singleMails in a thread-safe way.
type mailBuffer struct {
	mutex sync.Mutex
	mails []singleMail
}

// Push stores a new singleMail at the end of the mailBuffer.
func (mb *mailBuffer) Push(mail singleMail) error {
	mb.mutex.Lock()
	mb.mails = append(mb.mails, mail)
	mb.mutex.Unlock()
	return nil
}

// PushSlice stores a number of new singleMails at the end of the mailBuffer.
func (mb *mailBuffer) PushSlice(mails []singleMail) error {
	mb.mutex.Lock()
	for _, mail := range mails {
		mb.mails = append(mb.mails, mail)
	}
	mb.mutex.Unlock()
	return nil
}

// Pop retrieves an element off the end of the mailBuffer.
func (mb *mailBuffer) Pop() (singleMail, error) {
	mb.mutex.Lock()
	n := len(mb.mails) - 1
	if n < 0 {
		mb.mutex.Unlock()
		return singleMail{}, fmt.Errorf("no elements in buffer")
	}
	mail := mb.mails[n]
	mb.mails[n] = singleMail{}
	mb.mails = mb.mails[:n]
	mb.mutex.Unlock()
	return mail, nil
}

// Len returns the number of elements in the mailBuffer.
func (mb *mailBuffer) Len() uint32 {
	mb.mutex.Lock()
	n := len(mb.mails)
	mb.mutex.Unlock()
	return uint32(n)
}
