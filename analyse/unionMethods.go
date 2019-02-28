/*
@File : unionMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 08:38
*/

package analyse

import (
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/types"
	"analysePDNSByMonth/util"
	"analysePDNSByMonth/variables"
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

/*
	合并dns记录和ipv4地址
 */
func unionDNSRecordAndIP(dnsFileName string, ipFileName string, unionFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + dnsFileName + " & " + ipFileName + " -> " + unionFileName)

	if util.FileIsNotExist(unionFileName) {
		// 域名对应IP字典
		var domainIPMap= make(types.TPMSS)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		var fileLines = util.GetLines(ipFileName)
		var domain string

		// 读入ip文件，构建字典
		ipFile, eO := os.Open(ipFileName)
		if eO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
			os.Exit(1)
		}
		defer ipFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
		inIPFile := bufio.NewReader(ipFile)
		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("Create DomainIPMap, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			domainIPBytes, _, eR := inIPFile.ReadLine()
			if eR == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			domainIP := string(domainIPBytes)
			domainIPList := strings.Split(domainIP, "\t")
			domain = domainIPList[constants.UDomainIndex]
			if _, ok := domainIPMap[domain]; !ok {
				domainIPMap[domain] = domainIPList[constants.UIPv4Index]
			}
		}
		util.LogRecord(fmt.Sprintf("Create DomainIPMap, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

		// 创建合并文件
		unionFile, eOO := os.OpenFile(unionFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer unionFile.Close()
		if eOO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
			os.Exit(1)
		}
		outUnionFile := bufio.NewWriter(unionFile)

		// 打开dns文件，进行遍历
		readedCount = 0
		readedTotal = 0
		fileLines = util.GetLines(dnsFileName)

		dnsFile, eOOO := os.Open(dnsFileName)
		if eOOO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eOOO.Error()))
			os.Exit(1)
		}
		defer dnsFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
		inDnsFile := bufio.NewReader(dnsFile)
		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("Traversing DNSRecord and Union, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, eRR := inDnsFile.ReadLine()
			if eRR == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			domain = strings.Split(dnsRecord, "\t")[constants.UNDomainIndex]
			ipv4 := domainIPMap[domain]
			if ipv4 == "" {				// 是否需要此时查询
				ipv4 = "null;"
			}
			dnsRecordNew := dnsRecord + "\t" + ipv4

			// 写入合并后的文件
			_, eW := outUnionFile.WriteString(dnsRecordNew + "\n")
			if eW != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
				continue
			}
			outUnionFile.Flush()
		}
		util.LogRecord(fmt.Sprintf("Traversing DNSRecord and Union, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", unionFileName, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + dnsFileName + " & " + ipFileName + " -> " + unionFileName)
}
