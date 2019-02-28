/*
@File : nsv4Methods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 08:37
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
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

/*
	查询IPv4地址+字典
 */
func lookUpIPv4ByDomain(dnsRecord string) string {

	dnsRecordList := strings.Split(dnsRecord, "\t")
	dnsRecordDomain := dnsRecordList[0]

	var ip string
	var ipv4Flag string

	if _, ok := variables.DomainIPMap[dnsRecordDomain]; ok {
		util.LogRecord("exist: " + dnsRecordDomain)
		ip = variables.DomainIPMap[dnsRecordDomain]						// 不可放在if中
		if ip == "null" || strings.Contains(ip, ":") {
			ipv4Flag = "0"
		} else {
			ipv4Flag = "1"
		}
	} else {
		util.LogRecord("not-exist: " + dnsRecordDomain)
		ipList, err := net.LookupHost(dnsRecordDomain)
		if err != nil {
			ipv4Flag = "0"
			ip = "null"
		} else if strings.Contains(ipList[0], ":") {
			ipv4Flag = "0"
			ip = ipList[0]
		} else {
			ipv4Flag = "1"
			ip = ipList[0]
		}
		variables.DomainIPMap[dnsRecordDomain] = ip
	}

	dnsRecordListNew := append(dnsRecordList, ipv4Flag, ip)
	dnsRecordNew := strings.Join(dnsRecordListNew, "\t")
	return dnsRecordNew

}

/*
	查询文件中域名的IPv4地址+字典
 */
func lookUpIPv4ByFile(fileName string, fileNameNew string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + filepath.Base(fileName))

	if variables.DomainIPMap == nil {
		variables.DomainIPMap = make(types.TPMSS)
	}

	srcFile, err := os.Open(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err.Error())
		return
	}
	defer srcFile.Close()	// 该函数执行完毕退出前才会执行defer后的语句

	br := bufio.NewReader(srcFile)

	readedCount := 0
	var readedTotal uint64 = 0
	fileLines := util.GetLines(fileName)

	fw, err := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
		return
	}
	outWFile := bufio.NewWriter(fw) 													// 创建新的 Writer 对象

	for {
		if readedCount > 1 {
			readedCount = 0
			util.LogRecord("remaining: " + strconv.FormatInt(int64(fileLines - readedTotal), 10) + ", cost: " + strconv.Itoa(int(time.Now().Sub(timeNow) / time.Second)) + "s")
		}
		dnsRecordBytes, _, e := br.ReadLine()
		if e == io.EOF {
			break
		}

		readedCount++
		readedTotal++

		dnsRecord := string(dnsRecordBytes)
		dnsRecordNew := lookUpIPv4ByDomain(dnsRecord)

		_, err = outWFile.WriteString(dnsRecordNew + "\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
			continue
		}
		outWFile.Flush()
	}

	util.LogRecord("remaining: " + strconv.FormatInt(int64(fileLines - readedTotal), 10) + ", cost: " + strconv.Itoa(int(time.Now().Sub(timeNow) / time.Second)) + "s")

	util.LogRecord("Ending: " + filepath.Base(fileName))
}

/*
	并发查询IPv4地址+字典
 */
func lookUpIPv4ByDnsRecordMulCHByMap(dnsRecord string, dnsRecordNew chan<- string) {

	dnsRecordList := strings.Split(dnsRecord, "\t")
	dnsRecordDomain := dnsRecordList[0]

	var ip string
	var ipv4Flag string

	if _, ok := variables.DomainIPMap[dnsRecordDomain]; ok {
		util.LogRecord("exist" + ip)
		ip = variables.DomainIPMap[dnsRecordDomain]
		if ip == "null" || strings.Contains(ip, ":") {
			ipv4Flag = "0"
		} else {
			ipv4Flag = "1"
		}
	} else {
		util.LogRecord("not-exist" + ip)
		ipList, err := net.LookupHost(dnsRecordDomain)
		if err != nil {
			ipv4Flag = "0"
			ip = "null"
		} else if strings.Contains(ipList[0], ":") {
			ipv4Flag = "0"
			ip = ipList[0]
		} else {
			ipv4Flag = "1"
			ip = ipList[0]
		}
		variables.DomainIPMap[dnsRecordDomain] = ip					// 加锁???
	}

	dnsRecordListNew := append(dnsRecordList, ipv4Flag, ip)
	dnsRecordNewTemp := strings.Join(dnsRecordListNew, "\t")
	dnsRecordNew <- dnsRecordNewTemp

}

/*
	并发查询IPv4地址
 */
func lookUpIPv4ByDnsRecordMulCH(dnsRecord string, dnsRecordNew chan<- string) {
	dnsRecordList := strings.Split(dnsRecord, "\t")
	dnsRecordDomain := dnsRecordList[0]
	dnsRecordNewTemp := strings.Join(dnsRecordList, "\t") + "\t" + util.DNSLookUpIP(dnsRecordDomain)
	dnsRecordNew <- dnsRecordNewTemp
}

/*
	并发查询文件中域名的IPv4地址
 */
func lookUpIPv4ByFileMulCH(fileName string, fileNameNew string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " -> " + fileNameNew)

	if util.FileIsNotExist(fileNameNew) {
		srcFile, errr := os.Open(fileName)
		if errr != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", errr.Error()))
			os.Exit(1)
		}
		defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		dnsRecordNew := make(chan string) // 并发  							// 传递ipv4并发参数

		var err error
		var dnsRecordBytes []byte
		var i uint64
		fileLines := util.GetLines(fileName)

		fw, errw := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if errw != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", errw.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		for {
			for {
				if readedCount >= variables.LogShowSmlLag {
					util.LogRecord(fmt.Sprintf("remaining(chan->): %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
					break
				}
				dnsRecordBytes, _, err = br.ReadLine()
				if err == io.EOF {
					break
				}
				readedCount++
				readedTotal++
				dnsRecord := string(dnsRecordBytes)
				go lookUpIPv4ByDnsRecordMulCH(dnsRecord, dnsRecordNew) // 并发执行
			}

			// 并发输出
			for i = 0; i < readedCount; i++ {
				dnsRecordNewTemp := <-dnsRecordNew
				if i%(variables.LogShowSmlLag) == 0 {
					util.LogRecord(fmt.Sprintf("remaining(chan<-): %d, cost: %ds", fileLines-i, time.Now().Sub(timeNow)/time.Second))
					util.LogRecord("Example: " + dnsRecordNewTemp)
				}
				_, errw = outWFile.WriteString(dnsRecordNewTemp + "\n")
				if errw != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
					continue
				}
				outWFile.Flush()
			}

			fileLines -= readedCount
			readedCount = 0
			if err == io.EOF {
				break
			}
		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-i, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow)/time.Second))
	}

	util.LogRecord("Ending: " + fileName + " -> " + fileNameNew)
}

/*
	nslookup查询IP地址
 */
func lookUpIP(domains string) {
	domainList := strings.Split(strings.TrimRight(domains, ","), ",")
	for _, domain := range domainList {
		util.LogRecord(domain + "\t" + util.DNSLookUpIP(domain))
	}
}

/*
	zdnslookup查询IP地址
 */
func zdnslookUpIP(domains string) {
	domainList := strings.Split(strings.TrimRight(domains, ","), ",")
	for _, domain := range domainList {
		exe := "/bin/sh"
		zdnsCmd := fmt.Sprintf("echo %s | %s %s", domain, variables.ZDNSExeFileName, constants.ZDNSALookUp)
		cmd := []string{"-c", zdnsCmd}
		util.LogRecord(util.ZDNSLookUp(exe, cmd))
	}
}

/*
	zdnslookup查询IP地址
 */
func zdnslookUpIPByFile(fileName string, fileNameNew string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " -> " + fileNameNew)

	exe := variables.ZDNSExeFileName
	cmd := []string{constants.ZDNSALookUp, "-input-file", fileName, "-output-file", fileNameNew, "-threads", strconv.Itoa(variables.ZDNSThreads)}
	var fileLines uint64 = util.GetLines(fileName)
	timeNow = time.Now()
	dur, _ := time.ParseDuration(fmt.Sprintf("+%ds", fileLines / 150000 * 60))
	util.LogRecord(fmt.Sprintf("zdns ALookUp will end at %s", timeNow.Add(dur).String()))
	util.ZDNSLookUp(exe, cmd)

	util.LogRecord("Ending: " + fileName + " -> " + fileNameNew)
}
