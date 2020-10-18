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

// PopSlice retrieves a number of elements off the end of the mailBuffer.
func (mb *mailBuffer) PopSlice(elements int) ([]singleMail, error) {
	var mails []singleMail

	if elements < 1 {
		return mails, fmt.Errorf("need to fetch at least 1 element")
	}

	mb.mutex.Lock()
	mailCount := len(mb.mails)
	if mailCount < 1 {
		mb.mutex.Unlock()
		return mails, fmt.Errorf("no elements in buffer")
	}
	if elements < mailCount {
		start := mailCount - elements
		mails = mb.mails[start:]
		mb.mails = mb.mails[:start]
	} else {
		mails = mb.mails
		mb.mails = mb.mails[:0]
	}
	mb.mutex.Unlock()
	return mails, nil
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
