package dns

const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeANY   uint16 = 255
)

const (
	ClassIN  uint16 = 1
	ClassCH  uint16 = 3
	ClassHS  uint16 = 4
	ClassANY uint16 = 255
)

const (
	OpcodeQuery  uint16 = 0
	OpcodeIQuery uint16 = 1
	OpcodeStatus uint16 = 2
)

const (
	RCodeNoError  uint16 = 0
	RCodeFormErr  uint16 = 1
	RCodeServFail uint16 = 2
	RCodeNXDomain uint16 = 3
	RCodeNotImp   uint16 = 4
	RCodeRefused  uint16 = 5
)

const (
	flagQR     uint16 = 1 << 15
	flagAA     uint16 = 1 << 10
	flagTC     uint16 = 1 << 9
	flagRD     uint16 = 1 << 8
	flagRA     uint16 = 1 << 7
	maskOpcode uint16 = 0x7800
	maskRCode  uint16 = 0x000f
	shiftOp    uint16 = 11
)

func FlagsQR(flags uint16) bool       { return flags&flagQR != 0 }
func FlagsAA(flags uint16) bool       { return flags&flagAA != 0 }
func FlagsTC(flags uint16) bool       { return flags&flagTC != 0 }
func FlagsRD(flags uint16) bool       { return flags&flagRD != 0 }
func FlagsRA(flags uint16) bool       { return flags&flagRA != 0 }
func FlagsOpcode(flags uint16) uint16 { return (flags & maskOpcode) >> shiftOp }
func FlagsRCode(flags uint16) uint16  { return flags & maskRCode }

func BuildFlags(qr bool, opcode, rcode uint16, aa, tc, rd, ra bool) uint16 {
	var f uint16
	if qr {
		f |= flagQR
	}
	f |= (opcode << shiftOp) & maskOpcode
	if aa {
		f |= flagAA
	}
	if tc {
		f |= flagTC
	}
	if rd {
		f |= flagRD
	}
	if ra {
		f |= flagRA
	}
	f |= rcode & maskRCode
	return f
}

var typeNames = map[uint16]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypePTR:   "PTR",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeSRV:   "SRV",
	TypeANY:   "ANY",
}

var classNames = map[uint16]string{
	ClassIN:  "IN",
	ClassCH:  "CH",
	ClassHS:  "HS",
	ClassANY: "ANY",
}

func TypeToString(t uint16) string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + uitoa(t)
}

func ClassToString(c uint16) string {
	if s, ok := classNames[c]; ok {
		return s
	}
	return "CLASS" + uitoa(c)
}

func StringToType(s string) uint16 {
	for k, v := range typeNames {
		if v == s {
			return k
		}
	}
	return 0
}

func uitoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var buf [5]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
