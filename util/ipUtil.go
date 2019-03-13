/*
@File : ipUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 14:13
*/

package util

import (
	"analysePDNSByMonth/types"
	"analysePDNSByMonth/variables"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

/*
	IP1小于IP2
 */
func IP1LessIP2(ip1 net.IP, ip2 net.IP) bool {
	for i := 0; i < 16; i++ {
		if ip1[i] < ip2[i] {
			return true
		} else if ip1[i] > ip2[i] {
			return false
		}
	}
	return false
}

/*
	IP1小于等于IP2
 */
func IP1LessEqualIP2(ip1 net.IP, ip2 net.IP) bool {
	for i := 0; i < 16; i++ {
		if ip1[i] < ip2[i] {
			return true
		} else if ip1[i] > ip2[i] {
			return false
		}
	}
	return true
}

/*
	ns查询
 */
func NSLookUpIP1(host string) string {
	ipList, err := net.LookupIP(host)
	if err != nil {
		return "null;"
	} else {
		ipStr := ""
		for _, ip := range ipList  {
			ipStr = ipStr + ip.String() + ";"
		}
		return ipStr
	}
}

func NSLookUpHost(host string) string {
	ipList, err := net.LookupHost(host)		// 多个ip地址，包括v6+v4
	if err != nil {
		return "null;"
	} else {
		return strings.Join(ipList, ";")
	}
}

func DNSLookUpIP(host string) string {
	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	m.RecursionDesired = true

	//r, _, _ := c.Exchange(m, net.JoinHostPort(variables.DNSConfig.Servers[0], variables.DNSConfig.Port))

	// 提高timeout加快并发
	const timeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.TODO(), timeout)
	defer cancel()
	r, _, _ := c.ExchangeContext(ctx, m, net.JoinHostPort(variables.DNSConfig.Servers[0], variables.DNSConfig.Port))

	if r == nil {
		return "null;"
	}

	if r.Rcode != dns.RcodeSuccess {
		return "null;"
	}
	// Stuff must be in the answer section
	ipStr := ""
	for _, ip := range r.Answer {
		ipStr = ipStr + strings.Split(ip.String(), "\t")[4] + ";"
	}
	return ipStr
}

func ZDNSJson2String(jsonBytes []byte) string {
	if string(jsonBytes) == "" {
		return ""
	}

	var res types.ALookUpResult

	err := json.Unmarshal(jsonBytes, &res)
	if err != nil {
		return "null\tnull;"
	}

	var resStr bytes.Buffer

	if res.Status != "NOERROR" {
		resStr.WriteString(res.Name)
		resStr.WriteString("\tnull;")
		return resStr.String()
	}

	resStr.WriteString(res.Name)
	resStr.WriteByte('\t')
	resStr.WriteString(strings.Join(res.Data.IPv4Addresses, ";"))

	return resStr.String()
}

/*
	ZDNSA地址查询
 */
func ZDNSLookUp(exe string, argu []string) string {
	cmd := exec.Command(exe, argu...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	// 保证关闭输出流
	defer stdout.Close()
	// 运行命令
	if err := cmd.Start(); err != nil {
		LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	// 读取输出结果
	opBytes, err := ioutil.ReadAll(stdout)
	if err != nil {
		LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	return ZDNSJson2String(opBytes)
}
