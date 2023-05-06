package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/regions"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	"golang.org/x/crypto/ssh"
)

type Connection struct {
	*ssh.Client
	password string
}

func Connect(addr, user, password string) (*Connection, error) {
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, err
	}

	return &Connection{conn, password}, nil

}

func (conn *Connection) SendCommands(cmds ...string) ([]byte, error) {
	session, err := conn.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		return []byte{}, err
	}

	in, err := session.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}

	out, err := session.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}

	var output []byte

	go func(in io.WriteCloser, out io.Reader, output *[]byte) {
		var (
			line string
			r    = bufio.NewReader(out)
		)
		for {
			b, err := r.ReadByte()
			if err != nil {
				break
			}

			*output = append(*output, b)

			if b == byte('\n') {
				line = ""
				continue
			}

			line += string(b)

			if strings.HasSuffix(line, "password: ") {
				_, err = in.Write([]byte(conn.password + "\n"))
				if err != nil {
					break
				}
			}
		}
	}(in, out, &output)

	cmd := strings.Join(cmds, "; ")
	_, err = session.Output(cmd)
	if err != nil {
		return []byte{}, err
	}

	return output, nil
}

func main() {
	var (
		method    string
		address   string
		sshUser   string
		sshPasswd string
		secretID  string
		secretKey string
		domain    string
		record    string
		iface     string
	)
	flag.StringVar(&method, "method", "ssh", "use which method connect to remote. ssh or http is allowed.")
	flag.StringVar(&address, "address", "", "remote address")
	flag.StringVar(&sshUser, "user", "root", "user name of router ssh")
	flag.StringVar(&sshPasswd, "passwd", "", "password of the user")
	flag.StringVar(&secretID, "secretID", "", "secret id of tencent cloud dnspod")
	flag.StringVar(&secretKey, "secretKey", "", "secret key of tencent cloud dnspod")
	flag.StringVar(&domain, "domain", "b1uepi11.xyz", "domain name to be synced")
	flag.StringVar(&record, "record", "@", "record of the domain to be synced")
	flag.StringVar(&iface, "iface", "pppoe-wan", "the name of network device")
	flag.Parse()
	if method != "ssh" && method != "http" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if method == "ssh" && (len(sshUser) == 0 || len(sshPasswd) == 0) {
		flag.PrintDefaults()
		os.Exit(1)
	}
	if len(secretID) == 0 || len(secretKey) == 0 {
		flag.PrintDefaults()
		os.Exit(1)
	}
	credential := common.NewCredential(secretID, secretKey)
	client, err := dnspod.NewClient(credential, regions.Beijing, profile.NewClientProfile())
	if err != nil {
		log.Fatalf("create tencent cloud dnspod client failed: %v", err)
	}
	req := dnspod.NewDescribeRecordListRequest()
	req.Domain = &domain
	req.RecordType = common.StringPtr("A")
	resp, err := client.DescribeRecordList(req)
	if err != nil {
		log.Fatalf("describe record list failed: %v", err)
	}
	var rli *dnspod.RecordListItem
	for _, rl := range resp.Response.RecordList {
		if *rl.Name == record {
			rli = rl
		}
	}
	if rli == nil {
		log.Printf("can not found record: %v", record)
	}
	ssh, err := Connect(address, sshUser, sshPasswd)
	if err != nil {
		log.Fatalf("ssh to router failed: %v", err)
	}
	output, err := ssh.SendCommands(fmt.Sprintf("ip a | grep %s | grep inet | cut -f6 -d' '", iface))
	if err != nil {
		log.Fatalf("exec command on router failed: %v", err)
	}
	ip, _, err := net.ParseCIDR(strings.TrimSpace(string(output)))
	if err != nil {
		log.Fatalf("parse cidr failed: %v", err)
	}
	if ip.String() != *rli.Value {
		log.Printf("sync ssh public to %s.%s", record, domain)
		req := dnspod.NewModifyRecordRequest()
		req.RecordId = rli.RecordId
		req.Domain = &domain
		req.RecordType = rli.Type
		req.RecordLine = rli.Line
		req.RecordLineId = rli.LineId
		req.Value = common.StringPtr(ip.String())
		req.SubDomain = &record
		req.TTL = common.Uint64Ptr(60)
		req.Status = common.StringPtr("ENABLE")
		if _, err := client.ModifyRecord(req); err != nil {
			log.Fatalf("modify record %s.%s failed: %v", record, domain, err)
		}
		log.Printf("set %s.%s dns %s record to %s", record, domain, *rli.Type, ip.String())
		return
	}
	log.Println("nothing changed")
}
