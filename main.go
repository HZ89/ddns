package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/cloudflare-go"
	"golang.org/x/crypto/ssh"
)

// Connection represents an SSH connection to a remote host.
type Connection struct {
	client   *ssh.Client
	password string
}

// Connect establishes an SSH connection to the specified address using the provided username and password.
func Connect(addr, user, password string) (*Connection, error) {
	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Consider using a proper host key callback in production
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH server: %v", err)
	}

	return &Connection{client: client, password: password}, nil
}

// RunCommand executes a command on the remote host and returns its output.
func (conn *Connection) RunCommand(cmd string) (string, error) {
	session, err := conn.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %v", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return "", fmt.Errorf("command execution failed: %v, output: %s", err, string(output))
	}

	return strings.TrimSpace(string(output)), nil
}

// isGlobalUnicast checks if an IP address is a global unicast address.
func isGlobalUnicast(ip net.IP) bool {
	return ip.IsGlobalUnicast() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsInterfaceLocalMulticast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsLoopback() &&
		!ip.IsUnspecified()
}

func main() {
	var (
		method      string
		address     string
		sshUser     string
		sshPasswd   string
		domain      string
		record      string
		ifaceV4Name string
		ifcaeV6Name string
		apiToken    string
		zoneID      string
		ipAddrV4    string
		ipAddrV6    string
		dnsRecordV4 *cloudflare.DNSRecord
		dnsRecordV6 *cloudflare.DNSRecord
	)

	// Command-line flags
	flag.StringVar(&method, "method", "ssh", "Connection method: 'ssh' or 'http'")
	flag.StringVar(&address, "address", "", "Remote address (e.g., '192.168.1.1:22')")
	flag.StringVar(&sshUser, "user", "root", "SSH username")
	flag.StringVar(&sshPasswd, "passwd", "", "SSH password")
	flag.StringVar(&domain, "domain", "example.com", "Domain name to update")
	flag.StringVar(&record, "record", "@", "DNS record to update")
	flag.StringVar(&ifaceV4Name, "ifaceV4", "eth0", "Network interface name for ipv4 address on remote server")
	flag.StringVar(&ifcaeV6Name, "ifaceV6", ifaceV4Name, "Network infterface name for ipv6 address on local server")
	flag.StringVar(&apiToken, "api-token", os.Getenv("CLOUDFLARE_API_TOKEN"), "Cloudflare API token")
	flag.Parse()

	// Validate required inputs
	if apiToken == "" {
		log.Fatal("Cloudflare API token is required. Set it via the '-api-token' flag or 'CLOUDFLARE_API_TOKEN' environment variable.")
	}

	if method != "ssh" && method != "http" {
		log.Fatalf("Invalid method '%s'. Only 'ssh' and 'http' are supported.", method)
	}

	if method == "ssh" && (sshUser == "" || sshPasswd == "" || address == "") {
		log.Fatal("SSH method requires '-address', '-user', and '-passwd' parameters.")
	}

	// Initialize Cloudflare API client
	api, err := cloudflare.NewWithAPIToken(apiToken)
	if err != nil {
		log.Fatalf("Failed to create Cloudflare API client: %v", err)
	}

	ctx := context.Background()

	// Retrieve the zone ID for the specified domain
	zones, err := api.ListZones(ctx, domain)
	if err != nil || len(zones) == 0 {
		log.Fatalf("Failed to retrieve zone information for domain '%s': %v", domain, err)
	}
	zoneID = zones[0].ID

	// Retrieve DNS records for the domain
	dnsRecords, _, err := api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{Name: domain})
	if err != nil {
		log.Fatalf("Failed to list DNS records: %v", err)
	}

	// Find existing A and AAAA records
	for _, record := range dnsRecords {
		if record.Name == domain {
			switch record.Type {
			case "A":
				dnsRecordV4 = &record
			case "AAAA":
				dnsRecordV6 = &record
			}
		}
	}

	// Obtain the public IPv4 address
	switch method {
	case "ssh":
		conn, err := Connect(address, sshUser, sshPasswd)
		if err != nil {
			log.Fatalf("SSH connection failed: %v", err)
		}
		defer conn.client.Close()

		// Run command to get the public IP address
		cmd := fmt.Sprintf("ip -4 -o addr show dev %s | awk '{print $4}' | cut -d\"/\" -f1", ifaceV4Name)
		ipAddrV4, err = conn.RunCommand(cmd)
		if err != nil || ipAddrV4 == "" {
			log.Fatalf("Failed to retrieve IPv4 address via SSH: %v", err)
		}
	case "http":
		// Implement HTTP method if needed
		log.Fatal("HTTP method is not implemented yet.")
	}

	// Update A record if needed
	if dnsRecordV4 == nil || dnsRecordV4.Content != ipAddrV4 {
		recordType := "A"
		recordContent := ipAddrV4
		if dnsRecordV4 == nil {
			// Create new A record
			newRecord := cloudflare.CreateDNSRecordParams{
				Type:    recordType,
				Name:    record,
				Content: recordContent,
				TTL:     120,
			}
			_, err := api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), newRecord)
			if err != nil {
				log.Fatalf("Failed to create A record: %v", err)
			}
			log.Printf("Created new A record: %s -> %s", domain, recordContent)
		} else {
			// Update existing A record
			updateRecord := cloudflare.UpdateDNSRecordParams{
				ID:      dnsRecordV4.ID,
				Type:    dnsRecordV4.Type,
				Name:    dnsRecordV4.Name,
				Content: recordContent,
				TTL:     dnsRecordV4.TTL,
			}
			_, err := api.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), updateRecord)
			if err != nil {
				log.Fatalf("Failed to update A record: %v", err)
			}
			log.Printf("Updated A record: %s -> %s", domain, recordContent)
		}
	}

	// Obtain the public IPv6 address from the local interface
	ipAddrV6, err = getLocalIPv6Address(ifcaeV6Name)
	if err != nil {
		log.Fatalf("Failed to retrieve IPv6 address: %v", err)
	}

	// Update AAAA record if needed
	if dnsRecordV6 == nil || dnsRecordV6.Content != ipAddrV6 {
		recordType := "AAAA"
		recordContent := ipAddrV6
		if dnsRecordV6 == nil {
			// Create new AAAA record
			newRecord := cloudflare.CreateDNSRecordParams{
				Type:    recordType,
				Name:    record,
				Content: recordContent,
				TTL:     120,
			}
			_, err := api.CreateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), newRecord)
			if err != nil {
				log.Fatalf("Failed to create AAAA record: %v", err)
			}
			log.Printf("Created new AAAA record: %s -> %s", domain, recordContent)
		} else {
			// Update existing AAAA record
			updateRecord := cloudflare.UpdateDNSRecordParams{
				ID:      dnsRecordV6.ID,
				Type:    dnsRecordV6.Type,
				Name:    dnsRecordV6.Name,
				Content: recordContent,
				TTL:     dnsRecordV6.TTL,
			}
			_, err := api.UpdateDNSRecord(ctx, cloudflare.ZoneIdentifier(zoneID), updateRecord)
			if err != nil {
				log.Fatalf("Failed to update AAAA record: %v", err)
			}
			log.Printf("Updated AAAA record: %s -> %s", domain, recordContent)
		}
	}

	log.Println("DNS records updated successfully.")
}

// getLocalIPv6Address retrieves the first global unicast IPv6 address with a prefix length of 128 from the specified network interface.
func getLocalIPv6Address(interfaceName string) (string, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("failed to get interface '%s': %v", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses for interface '%s': %v", interfaceName, err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip == nil || ip.To4() != nil {
			continue // Skip IPv4 addresses
		}
		if isGlobalUnicast(ip) {
			prefixSize, _ := ipNet.Mask.Size()
			if prefixSize == 128 {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no global unicast IPv6 address with prefix length 128 found on interface '%s'", interfaceName)
}
