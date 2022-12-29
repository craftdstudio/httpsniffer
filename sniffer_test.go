package sniffer

import (
	"log"
	"testing"
)

func TestSniffer(t *testing.T) {
	s := New("en0", 80)
	s.Register(func(txn *Transaction) (*Transaction, error) {
		log.Println(txn.Request)
		return txn, nil
	})

	s.Listen()
}
