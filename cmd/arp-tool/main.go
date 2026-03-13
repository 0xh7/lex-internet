package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

func main() {
	iface := flag.String("i", "", "network interface")
	target := flag.String("t", "", "target IP for single lookup")
	subnet := flag.String("s", "", "subnet to scan (CIDR, e.g. 192.168.1.0/24)")
	showTable := flag.Bool("table", false, "show system ARP table")
	flag.Parse()

	if *showTable {
		printARPTable()
		return
	}

	if *target != "" {
		ip := net.ParseIP(*target)
		if ip == nil {
			fmt.Fprintf(os.Stderr, "arp-tool: invalid IP: %s\n", *target)
			os.Exit(1)
		}
		mac, err := lookupARP(ip, *iface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "arp-tool: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s is at %s\n", ip, mac)
		return
	}

	if *subnet != "" {
		scanSubnet(*subnet, *iface)
		return
	}

	flag.Usage()
}

func lookupARP(targetIP net.IP, ifaceName string) (string, error) {
	iface, src, err := resolveInterface(ifaceName)
	if err != nil {
		return "", err
	}

	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}
	defer conn.Close()

	_ = iface
	_ = src

	target := &net.UDPAddr{IP: targetIP, Port: 67}
	conn.WriteTo([]byte{0}, target)

	time.Sleep(200 * time.Millisecond)

	return readARPEntry(targetIP)
}

func readARPEntry(ip net.IP) (string, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("arp", "-a", ip.String())
	default:
		cmd = exec.Command("arp", "-n", ip.String())
	}

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("arp lookup failed for %s: %w", ip, err)
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip.String()) {
			fields := strings.Fields(line)
			for _, f := range fields {
				if len(f) == 17 && (strings.Contains(f, ":") || strings.Contains(f, "-")) {
					return f, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no ARP entry for %s", ip)
}

func scanSubnet(cidr string, ifaceName string) {
	const maxConcurrentProbes = 256

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arp-tool: invalid CIDR: %v\n", err)
		os.Exit(1)
	}

	iface, srcIP, err := resolveInterface(ifaceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arp-tool: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanning %s via %s (%s)\n", cidr, iface.Name, srcIP)
	fmt.Printf("%-18s  %s\n", "IP Address", "MAC Address")
	fmt.Println(strings.Repeat("-", 40))

	hosts := expandCIDR(network)
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrentProbes)
	for _, host := range hosts {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			conn, err := net.DialTimeout("udp4", fmt.Sprintf("%s:1", ip), 100*time.Millisecond)
			if err == nil {
				_, _ = conn.Write([]byte{0})
				_ = conn.Close()
			}
		}(host)
	}
	wg.Wait()

	time.Sleep(1500 * time.Millisecond)
	for _, host := range hosts {
		mac, err := readARPEntry(host)
		if err == nil {
			fmt.Printf("%-18s  %s\n", host, mac)
		}
	}
}

func printARPTable() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("arp", "-a")
	default:
		cmd = exec.Command("arp", "-an")
	}
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "arp-tool: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(string(out))
}

func resolveInterface(name string) (*net.Interface, net.IP, error) {
	if name != "" {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, nil, fmt.Errorf("interface %s: %w", name, err)
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			return nil, nil, fmt.Errorf("no addresses on %s", name)
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return iface, ipnet.IP.To4(), nil
			}
		}
		return nil, nil, fmt.Errorf("no IPv4 address on %s", name)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) != 6 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				return &iface, ipnet.IP.To4(), nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no suitable interface found")
}

func expandCIDR(network *net.IPNet) []net.IP {
	mask := binary.BigEndian.Uint32(network.Mask)
	start := binary.BigEndian.Uint32(network.IP.To4())
	end := (start & mask) | (^mask)

	var ips []net.IP
	for i := start + 1; i < end; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip)
	}
	return ips
}
