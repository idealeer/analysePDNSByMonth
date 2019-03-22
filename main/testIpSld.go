/*
@File : testIpSld.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-21 12:14
*/

package main

import (
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/types"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func testSLDIPv6(fileName string, fileNameNew string) {
	timeNow := time.Now()
	fmt.Println("Excuting: " + fileName + " -> " + fileNameNew)

	// 打开读取文件
	srcFile, eO := os.Open(fileName)
	if eO != nil {
		fmt.Printf("Error: %s", eO.Error())
		os.Exit(1)
	}
	defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	br := bufio.NewReader(srcFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0

	var resStr bytes.Buffer

	var ipv6SLDMap= make(types.TPMSTPMSS, constants.YWTimes) // 去重后ipv6-map：[ipv6]("v6-cty\tv4cty")

	for {
		if readedCount%10000 == 0 {
			readedCount = 0
			fmt.Printf("remaining: %d, cost: %ds\n", readedTotal, time.Now().Sub(timeNow)/time.Second)
		}
		dnsRecordBytes, _, e := br.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		dnsRecord := string(dnsRecordBytes)
		dnsRecordList := strings.Split(dnsRecord, "\t")
		dnsRecordDomain := dnsRecordList[0]

		dnsRecordSubDomainList := strings.Split(dnsRecordDomain, ".") // 域名各级
		dnsRecordSubDomainListLen := len(dnsRecordSubDomainList)
		// 不存在SLD
		if dnsRecordSubDomainListLen < 2 {
			continue
		}
		dnsRecordIPv6List := strings.Split(strings.Trim(dnsRecordList[2], ";"), ";")

		resStr.WriteString(dnsRecordSubDomainList[0])
		resStr.WriteByte('.')
		resStr.WriteString(dnsRecordSubDomainList[1])

		dnsRecordSLD := resStr.String()
		resStr.Reset()

		// 遍历IPv6
		for _, ipv6 := range dnsRecordIPv6List {
			if _, ok := ipv6SLDMap[ipv6]; !ok {
				m := make(types.TPMSS)
				ipv6SLDMap[ipv6] = m
			}
			if !strings.ContainsAny(ipv6SLDMap[ipv6][dnsRecordSLD], dnsRecordDomain) {
				ipv6SLDMap[ipv6][dnsRecordSLD] = ipv6SLDMap[ipv6][dnsRecordSLD] + dnsRecordDomain + ";"
			}
		}

	}

	// 创建写出文件
	fw, eOO := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw.Close()
	if eOO != nil {
		fmt.Printf("Error: %s", eOO.Error())
		os.Exit(1)
	}
	outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

	// 保存v6地理结果到JSon
	for ipv6, sldMap := range ipv6SLDMap {
		if len(sldMap) < 2 {
			continue
		}
		jsonBytes6, err6 := json.Marshal(sldMap)
		if err6 != nil {
			fmt.Printf("Error: %s", err6.Error())
			os.Exit(1)
		}

		_, eW := outWFile.WriteString(ipv6 + "\t" + string(jsonBytes6) + "\n")
		resStr.Reset()

		if eW != nil {
			fmt.Printf("Error: %s", eW.Error())
			os.Exit(1)
		}
		outWFile.Flush()
	}
	fmt.Printf("cost: %ds", time.Now().Sub(timeNow)/time.Second)
}

func main() {
	fn := "/Users/ida/文件/项目文件/ipv6测量/ipv6数据/pdns_ipv6/vps/error/20190302/part-00000"

	fnn := "/Users/ida/文件/项目文件/ipv6测量/ipv6数据/pdns_ipv6/vps/error/20190302/part-00000-ccc.txt"

	testSLDIPv6(fn, fnn)
}
