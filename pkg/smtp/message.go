package smtp

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/textproto"
	"strings"
	"time"
)

type Email struct {
	From      string
	To        []string
	Subject   string
	Body      string
	Headers   map[string]string
	Date      time.Time
	MessageID string
}

func ParseEmail(raw []byte) (*Email, error) {
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	mimeHeader, err := reader.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, err
	}

	headers := make(map[string]string, len(mimeHeader))
	for key, values := range mimeHeader {
		if len(values) > 0 {
			headers[key] = strings.Join(values, ", ")
		}
	}

	body, err := io.ReadAll(reader.R)
	if err != nil {
		return nil, err
	}

	email := &Email{
		Headers: headers,
		Body:    string(body),
	}

	if v, ok := headers["From"]; ok {
		email.From = v
	}
	if v, ok := headers["To"]; ok {
		for _, addr := range strings.Split(v, ",") {
			addr = strings.TrimSpace(addr)
			if addr != "" {
				email.To = append(email.To, addr)
			}
		}
	}
	if v, ok := headers["Subject"]; ok {
		email.Subject = v
	}
	if v, ok := headers["Message-ID"]; ok {
		email.MessageID = v
	}
	if v, ok := headers["Date"]; ok {
		if t, err := time.Parse(time.RFC1123Z, v); err == nil {
			email.Date = t
		} else if t, err := time.Parse("Mon, 2 Jan 2006 15:04:05 -0700", v); err == nil {
			email.Date = t
		}
	}

	return email, nil
}

func (e *Email) Marshal() []byte {
	var buf bytes.Buffer

	if e.MessageID != "" {
		fmt.Fprintf(&buf, "Message-ID: %s\r\n", e.MessageID)
	}
	if !e.Date.IsZero() {
		fmt.Fprintf(&buf, "Date: %s\r\n", e.Date.Format(time.RFC1123Z))
	}
	if e.From != "" {
		fmt.Fprintf(&buf, "From: %s\r\n", e.From)
	}
	if len(e.To) > 0 {
		fmt.Fprintf(&buf, "To: %s\r\n", strings.Join(e.To, ", "))
	}
	if e.Subject != "" {
		fmt.Fprintf(&buf, "Subject: %s\r\n", e.Subject)
	}

	skip := map[string]bool{
		"Message-Id": true, "Date": true, "From": true, "To": true, "Subject": true,
	}
	for k, v := range e.Headers {
		if skip[k] {
			continue
		}
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}

	buf.WriteString("\r\n")
	buf.WriteString(e.Body)
	return buf.Bytes()
}

func (e *Email) AddHeader(key, value string) {
	if e.Headers == nil {
		e.Headers = make(map[string]string)
	}
	e.Headers[textproto.CanonicalMIMEHeaderKey(key)] = value
}
