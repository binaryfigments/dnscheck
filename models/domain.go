package models

import "time"

// Question struct
type Question struct {
	JobDomain  string    `json:"JobDomain"`
	JobStatus  string    `json:"JobStatus"`
	JobMessage string    `json:"JobMessage"`
	JobTime    time.Time `json:"JobTime"`
}

// Answer struct
type Answer struct {
	DomainTLD         string          `json:"DomainTLD"`
	DomainTLDicann    bool            `json:"DomainTLDicann"`
	DomainTLDNS       []string        `json:"DomainTLDNS"`
	DSRecordCount     int             `json:"DSRecordCount"`
	DomainDS          []*DomainDS     `json:"DomainDS,omitempty"`
	DNSKEYRecordCount int             `json:"DNSKEYRecordCount"`
	DomainDNSKEY      []*DomainDNSKEY `json:"DomainDNSKEY,omitempty"`
	DomainCalcDS      []*DomainCalcDS `json:"DomainCalcDS,omitempty"`
	DomainNS          []string        `json:"DomainNS"`
	DomainA           []string        `json:"DomainA,omitempty"`
	DomainAAAA        []string        `json:"DomainAAAA,omitempty"`
	DomainMX          []string        `json:"DomainMX,omitempty"`
}

// Message for retunring
type Message struct {
	Question Question `json:"Question"`
	Answer   Answer   `json:"Answer"`
}

// DomainDS struct
type DomainDS struct {
	Algorithm  uint8  `json:"Algorithm,omitempty"`
	Digest     string `json:"Digest,omitempty"`
	DigestType uint8  `json:"DigestType,omitempty"`
	KeyTag     uint16 `json:"KeyTag,omitempty"`
}

// DomainCalcDS struct
type DomainCalcDS struct {
	Algorithm  uint8  `json:"Algorithm,omitempty"`
	Digest     string `json:"Digest,omitempty"`
	DigestType uint8  `json:"DigestType,omitempty"`
	KeyTag     uint16 `json:"KeyTag,omitempty"`
}

// DomainDNSKEY struct
type DomainDNSKEY struct {
	Algorithm uint8  `json:"Algorithm,omitempty"`
	Flags     uint16 `json:"Flags,omitempty"`
	Protocol  uint8  `json:"Protocol,omitempty"`
	PublicKey string `json:"PublicKey,omitempty"`
}
