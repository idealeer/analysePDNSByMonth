/*
@File : uniqMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 08:46
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
	"strconv"
	"strings"
	"time"
)

/*
	去除重复域名
 */
func uniqueDomain(fileName string, fileNameNew string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " -> " + fileNameNew)

	if util.FileIsNotExist(fileNameNew) {
		srcFile, err := os.Open(fileName)
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(fileName)

		var domainMap= make(types.TPMSS)

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := br.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")
			dnsRecordDomain := dnsRecordList[constants.UNDomainIndex]
			if _, ok := domainMap[dnsRecordDomain]; !ok {
				domainMap[dnsRecordDomain] = ""
			}
		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))

		fw, err := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 保存去重域名
		readedTotal = 0
		for domain, _ := range domainMap {
			if readedTotal%variables.LogShowBigLag == 0 {
				util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			readedTotal++
			_, err = outWFile.WriteString(domain + "\n")
			if err != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
				continue
			}
			outWFile.Flush()
		}
		util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + " -> " + fileNameNew)
}

/*
	地理：去除重复域名，签名：域名
 */
func uniqueDomainByGeo(fileName string, fileNameNew string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " -> " + fileNameNew)

	if util.FileIsNotExist(fileNameNew) {
		// 打开读取文件
		srcFile, eO := os.Open(fileName)
		if eO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
			os.Exit(1)
		}
		defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(fileName)

		var domainMap= make(types.TPMSS) // 去重后域名map：[域名]("v6-cty\tv4-cty")

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := br.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")
			dnsRecordDomain := dnsRecordList[constants.GeoDomainIndex]

			if domainMap[dnsRecordDomain] == "" {
				dnsRecordV6Cty := dnsRecordList[constants.GeoV6GIndex]
				dnsRecordV4Cty := dnsRecordList[constants.GeoV4GIndex]
				domainMap[dnsRecordDomain] = dnsRecordV6Cty + "\t" + dnsRecordV4Cty
			}
		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

		// 创建写出文件
		fw, eOO := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if eOO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 保存去重域名
		readedCount = 0
		readedTotal = 0
		for domain, cty := range domainMap {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			uniqDomainRecord := fmt.Sprintf("%s\t%s", domain, cty)
			readedCount++
			readedTotal++
			_, eW := outWFile.WriteString(uniqDomainRecord + "\n")
			if eW != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
				continue
			}
			outWFile.Flush()
		}
		util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}
	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + " -> " + fileNameNew)
}

/*
	地理：去除重复ipv6，签名：ipv6
 */
func uniqueIPv6ByGeo(fileName string, fileNameNew string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " -> " + fileNameNew)

	if util.FileIsNotExist(fileNameNew) {
		// 打开读取文件
		srcFile, eO := os.Open(fileName)
		if eO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
			os.Exit(1)
		}
		defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(fileName)

		var ipv6Map = make(types.TPMSS) // 去重后ipv6-map：[ipv6]("v6-cty\tv4cty")

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := br.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")
			dnsRecordIPv6List := strings.Split(strings.Trim(dnsRecordList[constants.GeoIPv6Index], ";"), ";")

			// 遍历IPv6
			for _, ipv6 := range dnsRecordIPv6List {
				if ipv6Map[ipv6] == "" {
					dnsRecordV6Cty := dnsRecordList[constants.GeoV6GIndex]
					dnsRecordV4Cty := dnsRecordList[constants.GeoV4GIndex]
					ipv6Map[ipv6] = dnsRecordV6Cty + "\t" + dnsRecordV4Cty
				}
			}

		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

		// 创建写出文件
		fw, eOO := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if eOO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 保存去重ipv6
		readedCount = 0
		readedTotal = 0
		for ipv6, cty := range ipv6Map {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			uniqDomainRecord := fmt.Sprintf("%s\t%s", ipv6, cty)
			readedCount++
			readedTotal++
			_, eW := outWFile.WriteString(uniqDomainRecord + "\n")
			if eW != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
				continue
			}
			outWFile.Flush()
		}
		util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + " -> " + fileNameNew)
}

/*
	地理：去除重复SLD，签名：SLD
 */
func uniqueSLDByGeo(fileName string, v6UniqSLDFile string, v4UniqSLDFile string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " -> " + v6UniqSLDFile + " && " + v4UniqSLDFile)

	// v6地理去重sld
	if util.FileIsNotExist(v6UniqSLDFile) {
		// 打开读取文件
		srcFile, eO := os.Open(fileName)
		if eO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
			os.Exit(1)
		}
		//defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(fileName)

		var sldMap= make(types.TPMSTPMSI64) // 去重后SLD-map：[country]([sld](count))

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := br.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")

			dnsRecordDomain := dnsRecordList[constants.GeoDomainIndex]                           // 域名
			dnsRecordSubDomainList := strings.Split(dnsRecordDomain, ".") // 域名各级
			dnsRecordSubDomainListLen := len(dnsRecordSubDomainList)
			// 不存在SLD
			if dnsRecordSubDomainListLen < 2 {
				continue
			}
			dnsRecordSLD := fmt.Sprintf("%s.%s", dnsRecordSubDomainList[dnsRecordSubDomainListLen-2], dnsRecordSubDomainList[dnsRecordSubDomainListLen-1])
			dnsRecordCount, _ := strconv.ParseInt(dnsRecordList[constants.GeoCountIndex], 10, 64)   // 次数
			dnsRecordV6Cty := dnsRecordList[constants.GeoV6GIndex]

			// 国家是否存在
			if sldMap[dnsRecordV6Cty] == nil {
				sMap := make(types.TPMSI64)
				sldMap[dnsRecordV6Cty] = sMap
			}
			sldMap[dnsRecordV6Cty][dnsRecordSLD] += dnsRecordCount

		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

		srcFile.Close()	// 关闭源文件
		// 创建写出文件
		fw, eOO := os.OpenFile(v6UniqSLDFile, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if eOO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
			return
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 保存去重域名
		readedCount = 0
		readedTotal = 0
		for country, sMap := range sldMap {
			for sld, count := range sMap {
				if readedCount%variables.LogShowBigLag == 0 {
					readedCount = 0
					util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
				}
				uniqSLDRecord := fmt.Sprintf("%s\t%d\t%s", sld, count, country)
				readedCount++
				readedTotal++
				_, eW := outWFile.WriteString(uniqSLDRecord + "\n")
				if eW != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
					continue
				}
				outWFile.Flush()
			}
		}
		util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", v6UniqSLDFile, time.Now().Sub(timeNow)/time.Second))
	}

	// v4地理去重sld
	if util.FileIsNotExist(v4UniqSLDFile) {
		// 打开读取文件
		srcFile, eO := os.Open(fileName)
		if eO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
			os.Exit(1)
		}
		defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(fileName)

		var sldMap= make(types.TPMSTPMSI64) // 去重后SLD-map：[country]([sld](count))

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := br.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")

			dnsRecordDomain := dnsRecordList[constants.GeoDomainIndex]                           // 域名
			dnsRecordSubDomainList := strings.Split(dnsRecordDomain, ".") // 域名各级
			dnsRecordSubDomainListLen := len(dnsRecordSubDomainList)
			// 不存在SLD
			if dnsRecordSubDomainListLen < 2 {
				continue
			}
			dnsRecordSLD := fmt.Sprintf("%s.%s", dnsRecordSubDomainList[dnsRecordSubDomainListLen-2], dnsRecordSubDomainList[dnsRecordSubDomainListLen-1])
			dnsRecordCount, _ := strconv.ParseInt(dnsRecordList[constants.GeoCountIndex], 10, 64)   // 次数
			dnsRecordV6Cty := dnsRecordList[constants.GeoV4GIndex]

			// 国家是否存在
			if sldMap[dnsRecordV6Cty] == nil {
				sMap := make(types.TPMSI64)
				sldMap[dnsRecordV6Cty] = sMap
			}
			sldMap[dnsRecordV6Cty][dnsRecordSLD] += dnsRecordCount

		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

		// 创建写出文件
		fw, eOO := os.OpenFile(v4UniqSLDFile, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if eOO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
			return
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 保存去重域名
		readedCount = 0
		readedTotal = 0
		for country, sMap := range sldMap {
			for sld, count := range sMap {
				if readedCount%variables.LogShowBigLag == 0 {
					readedCount = 0
					util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
				}
				uniqSLDRecord := fmt.Sprintf("%s\t%d\t%s", sld, count, country)
				readedCount++
				readedTotal++
				_, eW := outWFile.WriteString(uniqSLDRecord + "\n")
				if eW != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
					continue
				}
				outWFile.Flush()
			}
		}
		util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", v4UniqSLDFile, time.Now().Sub(timeNow)/time.Second))
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + " -> " + v6UniqSLDFile + " && " + v4UniqSLDFile)
}

/*
	去除重复TLD
 */
func uniqueTLD(fileName string, fileNameNew string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " -> " + fileNameNew)

	if util.FileIsNotExist(fileNameNew) {
		srcFile, err := os.Open(fileName)
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(fileName)

		var tldMap = make(types.TPMSI64)

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := br.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")
			dnsRecordDomain := dnsRecordList[constants.UNDomainIndex]
			dnsRecordSubDomainList := strings.Split(dnsRecordDomain, ".") // 域名各级
			dnsRecordSubDomainListLen := len(dnsRecordSubDomainList)
			// 不存在TLD
			if dnsRecordSubDomainListLen < 1 {
				continue
			}
			dnsRecordTLD := dnsRecordSubDomainList[dnsRecordSubDomainListLen-1]
			dnsRecordTimes, _ := strconv.ParseInt(dnsRecordList[constants.GeoCountIndex], 10, 64)               // 请求次数，解析为uint会出错

			tldMap[dnsRecordTLD] += dnsRecordTimes

		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))

		fw, err := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 保存去重域名
		readedTotal = 0
		for tld, count := range tldMap {
			if readedTotal%variables.LogShowBigLag == 0 {
				util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			readedTotal++
			_, err = outWFile.WriteString(fmt.Sprintf("%s\t%d\n", tld, count))
			if err != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
				continue
			}
			outWFile.Flush()
		}
		util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + " -> " + fileNameNew)
}
