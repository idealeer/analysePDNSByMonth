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
	"encoding/json"
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

/*
	合并Json文件
 */
func unionJsonResult(fileBefore string, fileNow string, fileTotal string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileBefore + " & " + fileNow + " -> " + fileTotal)

	// 结果Map
	var beforeMap = make(types.TPMSTPMSTPMSI64)
	var nowMap = make(types.TPMSTPMSTPMSI64)
	//var totalMap = make(types.TPMSTPMSTPMSI64)		// beforeMap -> totalMap


	// 读入先前Json结果，构建字典
	beforeFile, eO := os.Open(fileBefore)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
		os.Exit(1)
	}
	defer beforeFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inBeforeFile := bufio.NewReader(beforeFile)
	beforeJsonBytes, _, eR := inBeforeFile.ReadLine()
	if eR == io.EOF {
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileBefore))
		os.Exit(1)
	}
	eU := json.Unmarshal(beforeJsonBytes, &beforeMap)
	if eU != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileBefore, eU.Error()))
		os.Exit(1)
	}

	// 读入当前Json结果，构建字典
	nowFile, eO0 := os.Open(fileNow)
	if eO0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO0.Error()))
		os.Exit(1)
	}
	defer nowFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inNowFile := bufio.NewReader(nowFile)
	nowJsonBytes, _, eR0 := inNowFile.ReadLine()
	if eR0 == io.EOF {
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileNow))
		os.Exit(1)
	}
	eU0 := json.Unmarshal(nowJsonBytes, &nowMap)
	if eU0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileNow, eU0.Error()))
		os.Exit(1)
	}

	// 合并结果
	for geo, _ := range nowMap {
		for country, mcMap := range nowMap[geo] {
			if beforeMap[geo][country] == nil {
				tempMap := make(types.TPMSI64)
				beforeMap[geo][country] = tempMap
			}
			for m, c := range mcMap {
				beforeMap[geo][country][m] += c
			}
		}
	}

	// 保存结果到JSon
	jsonBytes, err := json.Marshal(beforeMap)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(fileTotal, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw.Close()
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象
	_, err = outWFile.WriteString(string(jsonBytes) + "\n")
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	outWFile.Flush()

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileBefore + " & " + fileNow + " -> " + fileTotal)
}
