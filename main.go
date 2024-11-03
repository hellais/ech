package main

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type DNSQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type DNSResponse struct {
	Status   int           `json:"Status"`
	TC       bool          `json:"TC"`
	RD       bool          `json:"RD"`
	RA       bool          `json:"RA"`
	AD       bool          `json:"AD"`
	CD       bool          `json:"CD"`
	Question []DNSQuestion `json:"Question"`
	Answer   []DNSAnswer   `json:"Answer"`
}

type HttpsRecord struct {
	Priority   uint16
	TargetName string
	Params     []SvcParam
}

type SvcParam struct {
	Key   uint16
	Value []byte
}

// Parse HTTPS data
func parseHttpsRecord(data []byte) (*HttpsRecord, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("invalid data length")
	}

	record := &HttpsRecord{}

	// Read Priority (2 bytes)
	record.Priority = uint16(data[0])<<8 | uint16(data[1])

	// Target Name: variable length, null-terminated
	idx := 2
	for idx < len(data) && data[idx] != 0 {
		idx++
	}
	if idx >= len(data) {
		return nil, fmt.Errorf("invalid target name in data")
	}
	record.TargetName = string(data[2:idx])
	idx++ // Move past the null byte

	// Parse SvcParams
	for idx+4 <= len(data) {
		key := uint16(data[idx])<<8 | uint16(data[idx+1])
		length := int(data[idx+2])<<8 | int(data[idx+3])
		idx += 4

		if idx+length > len(data) {
			return nil, fmt.Errorf("invalid parameter length")
		}

		value := data[idx : idx+length]
		record.Params = append(record.Params, SvcParam{Key: key, Value: value})
		idx += length
	}

	return record, nil
}

func getECHConfig(hostname string) ([]byte, error) {
	client := &http.Client{}
	url, err := url.Parse(fmt.Sprintf("https://cloudflare-dns.com/dns-query?name=%s&type=https", hostname))
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	resp, err := client.Do(&http.Request{
		Method: "GET",
		Header: map[string][]string{
			"Accept": {"application/dns-json"},
		},
		URL: url,
	})
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	fmt.Println(string(data))
	dnsResponse := DNSResponse{}
	err = json.Unmarshal(data, &dnsResponse)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	// Data looks like: "\# 58 00 01 00 00 01 00 03 02 68 32 00 04 00 08 a2 9f 87 4f a2 9f 88 4f 00 06 00 20 26 06 47 00 00 07 00 00 00 00 00 00 a2 9f 87 4f 26 06 47 00 00 07 00 00 00 00 00 00 a2 9f 88 4f"
	log.Printf("answer: %s\n", dnsResponse.Answer[0].Data)

	// Parse the Data field into bytes
	dataBytes, err := hex.DecodeString(strings.Join(strings.Split(dnsResponse.Answer[0].Data, " ")[2:], ""))
	if err != nil {
		log.Fatalf("failed to decode data: %v", err)
		return nil, err
	}

	record, err := parseHttpsRecord(dataBytes)
	if err != nil {
		log.Fatalf("failed to decode record: %v", err)
		return nil, err
	}
	var echConfig []byte
	for _, param := range record.Params {
		// ECHConfig is 5 (see: https://www.ietf.org/archive/id/draft-ietf-dnsop-svcb-https-07.html#section-14.3.2)
		if param.Key == 0x05 {
			echConfig = param.Value
		}
	}
	return echConfig, nil
}

func main() {
	//hostname := "crypto.cloudflare.com"
	hostname := "research.cloudflare.com"
	echBytes, err := getECHConfig(hostname)
	if err != nil || len(echBytes) == 0 {
		log.Fatalf("failed to get ech config: %v", err)
	}

	tlsConfig := &tls.Config{
		EncryptedClientHelloConfigList: echBytes,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", hostname), tlsConfig)
	if err != nil {
		log.Fatalf("could not connect to server: %v", err)
	}
	defer conn.Close()
	fmt.Println("Connected to server via TLS")

	message := fmt.Sprintf("GET /cdn-cgi/trace HTTP/1.1\nHost: %s\n\n", hostname)
	_, err = conn.Write([]byte(message))
	if err != nil {
		log.Fatalf("failed to send message: %v", err)
	}
	fmt.Printf("Sent message: %s\n", message)

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	if err != nil {
		log.Fatalf("failed to read response: %v", err)
	}
	fmt.Printf("Received reply: %s\n", string(reply[:n]))
}
