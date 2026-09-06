package discover

import (
	"bufio"
	"net"
	"strings"
)

// Neighbor is one entry of the operating system's ARP/neighbour table: the only place
// a MAC address can be read without sending a single packet.
type Neighbor struct {
	IP  net.IP
	MAC string
}

// parseProcNetARP reads the Linux neighbour table.
//
//	IP address  HW type  Flags  HW address         Mask  Device
//	192.168.1.1 0x1      0x2    aa:bb:cc:dd:ee:ff  *     eth0
func parseProcNetARP(contents string) []Neighbor {
	found := []Neighbor{}
	scanner := bufio.NewScanner(strings.NewReader(contents))

	for line := 0; scanner.Scan(); line++ {
		if line == 0 {
			continue // header
		}

		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		ip := net.ParseIP(fields[0])
		mac := NormaliseMAC(fields[3])

		if ip == nil || mac == "" {
			continue
		}

		found = append(found, Neighbor{IP: ip, MAC: mac})
	}

	return found
}

// parseArpCommand reads the BSD and macOS form.
//
//	? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
func parseArpCommand(contents string) []Neighbor {
	found := []Neighbor{}
	scanner := bufio.NewScanner(strings.NewReader(contents))

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())

		for index, field := range fields {
			if field != "at" || index == 0 || index+1 >= len(fields) {
				continue
			}

			ip := net.ParseIP(strings.Trim(fields[index-1], "()"))
			mac := NormaliseMAC(fields[index+1])

			if ip == nil || mac == "" {
				continue
			}

			found = append(found, Neighbor{IP: ip, MAC: mac})

			break
		}
	}

	return found
}

// NormaliseMAC returns the lower-case colon-separated form, so one device cannot appear
// twice because two sources spelled its address differently. Incomplete entries — the
// table's placeholder for an address it never resolved — come back empty.
func NormaliseMAC(value string) string {
	hex := make([]byte, 0, 12)

	for index := 0; index < len(value); index++ {
		character := value[index]

		switch {
		case character >= '0' && character <= '9', character >= 'a' && character <= 'f':
			hex = append(hex, character)
		case character >= 'A' && character <= 'F':
			hex = append(hex, character+('a'-'A'))
		}
	}

	// BSD prints single-digit octets, so pad what is clearly a short but complete address.
	if len(hex) != 12 {
		if padded, ok := padShortMAC(value); ok {
			hex = padded
		} else {
			return ""
		}
	}

	if string(hex) == "000000000000" {
		return ""
	}

	// A broadcast or multicast address is not a host. The ARP table holds them, and
	// letting them through would invent a device whose address changes every sweep.
	if string(hex) == "ffffffffffff" || isMulticastMAC(hex) {
		return ""
	}

	out := make([]byte, 0, 17)
	for index := 0; index < 12; index += 2 {
		if index > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[index], hex[index+1])
	}

	return string(out)
}

// padShortMAC turns "a:b:c:d:e:f" into twelve hex digits. BSD's arp drops leading zeros.
func padShortMAC(value string) ([]byte, bool) {
	octets := strings.Split(value, ":")
	if len(octets) != 6 {
		return nil, false
	}

	hex := make([]byte, 0, 12)

	for _, octet := range octets {
		if len(octet) == 0 || len(octet) > 2 {
			return nil, false
		}

		if len(octet) == 1 {
			hex = append(hex, '0')
		}

		for index := 0; index < len(octet); index++ {
			character := octet[index]
			switch {
			case character >= '0' && character <= '9', character >= 'a' && character <= 'f':
				hex = append(hex, character)
			case character >= 'A' && character <= 'F':
				hex = append(hex, character+('a'-'A'))
			default:
				return nil, false
			}
		}
	}

	return hex, true
}

// isMulticastMAC reports whether the group bit — the low bit of the first octet — is set.
func isMulticastMAC(hex []byte) bool {
	if len(hex) < 2 {
		return false
	}

	value, ok := hexByte(hex[0], hex[1])

	return ok && value&1 == 1
}

// hexByte decodes two lower-case hex digits.
func hexByte(high, low byte) (byte, bool) {
	decode := func(character byte) (byte, bool) {
		switch {
		case character >= '0' && character <= '9':
			return character - '0', true
		case character >= 'a' && character <= 'f':
			return character - 'a' + 10, true
		}

		return 0, false
	}

	first, ok := decode(high)
	if !ok {
		return 0, false
	}

	second, ok := decode(low)
	if !ok {
		return 0, false
	}

	return first<<4 | second, true
}
