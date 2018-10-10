package main

import (
	"encoding/json"
	"fmt"
	"strconv"

	httpclient "github.com/ddliu/go-httpclient"
)

const (
	QueryRetryTimes = 5
	UserAgent       = "go-pixiv"
	WfJSON          = "application/dns-json"
)

type DNSQuery struct {
	name     string
	rrtype   string
	endpoint string
	dnssec   bool
	insecure bool
}

func (c *DNSQuery) Do() (*DNSQueryResponse, error) {
	url := fmt.Sprintf("%s?ct=%s&name=%s&type=%s&do=%s&cd=%s", c.endpoint, WfJSON, c.name, c.rrtype, strconv.FormatBool(c.dnssec), strconv.FormatBool(c.insecure))
	var err error
	var respbytes []byte
	for i := 0; i < QueryRetryTimes; i++ {
		resp, err := httpclient.
			Begin().
			WithHeader("User-Agent", UserAgent).
			Get(url)
		if err != nil {
			continue
		}
		respbytes, err = resp.ReadAll()
		if err != nil {
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	answer := &DNSQueryResponse{}
	err = json.Unmarshal(respbytes, answer)
	return answer, err
}

type DNSQueryResponse struct {
	Status               int           `json:"Status"`
	Truncated            bool          `json:"TC"`
	RecursiveDesired     bool          `json:"RD"`
	RecursiveAvailable   bool          `json:"RA"`
	DNSSECVerified       bool          `json:"AD"`
	DNSSECVerifyDisabled bool          `json:"CD"`
	Question             []DNSQuestion `json:"Question"`
	Answer               []DNSAnswer   `json:"Answer"`
}
type DNSQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}
type DNSAnswer struct {
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}
