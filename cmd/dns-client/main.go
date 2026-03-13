package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/0xh7/lex-internet/pkg/dns"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: dns-client [@server] name [type]\n")
		os.Exit(1)
	}

	server := "8.8.8.8:53"
	var name string
	qtype := dns.TypeA
	verbose := false

	var positional []string
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "@"):
			s := arg[1:]
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(s, "53")
			}
			server = s
		case arg == "-v" || arg == "--verbose":
			verbose = true
		default:
			positional = append(positional, arg)
		}
	}

	if len(positional) == 0 {
		fmt.Fprintf(os.Stderr, "error: no query name specified\n")
		os.Exit(1)
	}

	name = positional[0]
	if len(positional) > 1 {
		t := dns.StringToType(strings.ToUpper(positional[1]))
		if t == 0 {
			fmt.Fprintf(os.Stderr, "error: unknown record type: %s\n", positional[1])
			os.Exit(1)
		}
		qtype = t
	}

	resolver := dns.NewResolver(server)
	resolver.SetTimeout(5 * time.Second)

	start := time.Now()
	msg, err := resolver.Resolve(name, qtype)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printHeader(msg, server)

	if verbose {
		printFlags(msg)
	}

	if len(msg.Questions) > 0 {
		fmt.Println(";; QUESTION SECTION:")
		for _, q := range msg.Questions {
			fmt.Printf(";%-23s %-7s %s\n", q.Name+".", dns.ClassToString(q.Class), dns.TypeToString(q.Type))
		}
		fmt.Println()
	}

	if len(msg.Answers) > 0 {
		fmt.Println(";; ANSWER SECTION:")
		for _, rr := range msg.Answers {
			printRR(rr)
		}
		fmt.Println()
	}

	if len(msg.Authority) > 0 {
		fmt.Println(";; AUTHORITY SECTION:")
		for _, rr := range msg.Authority {
			printRR(rr)
		}
		fmt.Println()
	}

	if verbose && len(msg.Additional) > 0 {
		fmt.Println(";; ADDITIONAL SECTION:")
		for _, rr := range msg.Additional {
			printRR(rr)
		}
		fmt.Println()
	}

	fmt.Printf(";; Query time: %d msec\n", elapsed.Milliseconds())
	fmt.Printf(";; SERVER: %s\n", server)
	fmt.Printf(";; MSG SIZE  rcvd: %d\n", estimateSize(msg))
}

func printHeader(msg *dns.Message, server string) {
	opcode := dns.FlagsOpcode(msg.Header.Flags)
	rcode := dns.FlagsRCode(msg.Header.Flags)
	status := rcodeStr(rcode)

	opcodeStr := "QUERY"
	if opcode == dns.OpcodeIQuery {
		opcodeStr = "IQUERY"
	} else if opcode == dns.OpcodeStatus {
		opcodeStr = "STATUS"
	}

	fmt.Printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n", opcodeStr, status, msg.Header.ID)
	fmt.Printf(";; flags:")
	if dns.FlagsQR(msg.Header.Flags) {
		fmt.Print(" qr")
	}
	if dns.FlagsAA(msg.Header.Flags) {
		fmt.Print(" aa")
	}
	if dns.FlagsTC(msg.Header.Flags) {
		fmt.Print(" tc")
	}
	if dns.FlagsRD(msg.Header.Flags) {
		fmt.Print(" rd")
	}
	if dns.FlagsRA(msg.Header.Flags) {
		fmt.Print(" ra")
	}
	fmt.Printf("; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n",
		len(msg.Questions), len(msg.Answers), len(msg.Authority), len(msg.Additional))
}

func printFlags(msg *dns.Message) {
	fmt.Printf(";; Flags: 0x%04x\n", msg.Header.Flags)
	fmt.Printf(";;   QR=%v AA=%v TC=%v RD=%v RA=%v\n",
		dns.FlagsQR(msg.Header.Flags),
		dns.FlagsAA(msg.Header.Flags),
		dns.FlagsTC(msg.Header.Flags),
		dns.FlagsRD(msg.Header.Flags),
		dns.FlagsRA(msg.Header.Flags))
	fmt.Println()
}

func printRR(rr dns.ResourceRecord) {
	name := rr.Name
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	rdata := formatRData(rr)
	fmt.Printf("%-23s %-7d %-7s %-7s %s\n",
		name, rr.TTL, dns.ClassToString(rr.Class), dns.TypeToString(rr.Type), rdata)
}

func formatRData(rr dns.ResourceRecord) string {
	switch rr.Type {
	case dns.TypeA:
		if len(rr.RData) == 4 {
			return net.IP(rr.RData).String()
		}
	case dns.TypeAAAA:
		if len(rr.RData) == 16 {
			return net.IP(rr.RData).String()
		}
	case dns.TypeCNAME, dns.TypeNS, dns.TypePTR:
		return decodeLabelSequence(rr.RData) + "."
	case dns.TypeMX:
		if len(rr.RData) >= 3 {
			pref := binary.BigEndian.Uint16(rr.RData[:2])
			exchange := decodeLabelSequence(rr.RData[2:])
			return fmt.Sprintf("%d %s.", pref, exchange)
		}
	case dns.TypeTXT:
		return "\"" + decodeTXTRdata(rr.RData) + "\""
	case dns.TypeSOA:
		return formatSOA(rr.RData)
	case dns.TypeSRV:
		if len(rr.RData) >= 7 {
			pri := binary.BigEndian.Uint16(rr.RData[0:2])
			weight := binary.BigEndian.Uint16(rr.RData[2:4])
			port := binary.BigEndian.Uint16(rr.RData[4:6])
			target := decodeLabelSequence(rr.RData[6:])
			return fmt.Sprintf("%d %d %d %s.", pri, weight, port, target)
		}
	}
	return fmt.Sprintf("\\# %d %x", len(rr.RData), rr.RData)
}

func decodeLabelSequence(data []byte) string {
	var parts []string
	off := 0
	for off < len(data) {
		length := int(data[off])
		if length == 0 {
			break
		}
		off++
		if off+length > len(data) {
			break
		}
		parts = append(parts, string(data[off:off+length]))
		off += length
	}
	return strings.Join(parts, ".")
}

func decodeTXTRdata(data []byte) string {
	var parts []string
	off := 0
	for off < len(data) {
		length := int(data[off])
		off++
		if off+length > len(data) {
			break
		}
		parts = append(parts, string(data[off:off+length]))
		off += length
	}
	return strings.Join(parts, "")
}

func formatSOA(rdata []byte) string {
	off := 0
	mname, off := readLabelSeq(rdata, off)
	rname, off := readLabelSeq(rdata, off)
	if off+20 > len(rdata) {
		return fmt.Sprintf("%s %s ...", mname, rname)
	}
	serial := binary.BigEndian.Uint32(rdata[off:])
	refresh := binary.BigEndian.Uint32(rdata[off+4:])
	retry := binary.BigEndian.Uint32(rdata[off+8:])
	expire := binary.BigEndian.Uint32(rdata[off+12:])
	minimum := binary.BigEndian.Uint32(rdata[off+16:])
	return fmt.Sprintf("%s. %s. %d %d %d %d %d", mname, rname, serial, refresh, retry, expire, minimum)
}

func readLabelSeq(data []byte, off int) (string, int) {
	var parts []string
	for off < len(data) {
		length := int(data[off])
		if length == 0 {
			off++
			break
		}
		off++
		if off+length > len(data) {
			break
		}
		parts = append(parts, string(data[off:off+length]))
		off += length
	}
	return strings.Join(parts, "."), off
}

func rcodeStr(code uint16) string {
	switch code {
	case dns.RCodeNoError:
		return "NOERROR"
	case dns.RCodeFormErr:
		return "FORMERR"
	case dns.RCodeServFail:
		return "SERVFAIL"
	case dns.RCodeNXDomain:
		return "NXDOMAIN"
	case dns.RCodeNotImp:
		return "NOTIMP"
	case dns.RCodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", code)
}

func estimateSize(msg *dns.Message) int {
	data, err := msg.Marshal()
	if err != nil {
		return 0
	}
	return len(data)
}
