/*
@File : analyseByGeoMethod.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-28 08:25
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
	"sort"
	"strconv"
	"strings"
	"time"
)

/*
	统计dns请求次数
 */
func analyseDNSRequestTimesByGeo(fileName string, resFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName)

	// 创建存储结构, map[v4/6](map[国家](map[月份]次数))
	var dnsRQCByVCD = make(types.TPMSTPMSTPMSI64)
	// v4/v6地理是否存在
	if dnsRQCByVCD[constants.V4GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		dnsRQCByVCD[constants.V4GeoString] = cmcMap
	}
	if dnsRQCByVCD[constants.V6GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		dnsRQCByVCD[constants.V6GeoString] = cmcMap
	}
	// 添加总计国家
	if dnsRQCByVCD[constants.V4GeoString][constants.TotalTimesString] == nil {
		mcMap := make(types.TPMSI64)
		dnsRQCByVCD[constants.V4GeoString][constants.TotalTimesString] = mcMap
	}
	if dnsRQCByVCD[constants.V6GeoString][constants.TotalTimesString] == nil {
		mcMap := make(types.TPMSI64)
		dnsRQCByVCD[constants.V6GeoString][constants.TotalTimesString] = mcMap
	}
	
	// 打开dns记录文件
	srcFile, eO := os.Open(fileName)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
		os.Exit(1)
	}
	defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

	inFile := bufio.NewReader(srcFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	fileLines := util.GetLines(fileName)

	if fileLines == 0 {
		util.LogRecord(fmt.Sprintf("%s is null, no need to Analyse.", fileName))
		return
	}

	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		dnsRecordBytes, _, e := inFile.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		dnsRecord := string(dnsRecordBytes)
		dnsRecordList := strings.Split(dnsRecord, "\t")

		dnsRecordTimes, _ := strconv.ParseInt(dnsRecordList[constants.GeoCountIndex], 10, 64)               // 请求次数，解析为uint会出错
		dnsRecordV6CTY := strings.Split(dnsRecordList[constants.GeoV6GIndex], ";")[constants.MMCNNameIndex] 		// V6地理-中文国家名
		dnsRecordV4CTY := strings.Split(dnsRecordList[constants.GeoV4GIndex], ";")[constants.MMCNNameIndex] 		// V4地理-中文国家名

		// v6地理-国家是否存在
		if dnsRecordV6CTY != "null" {
			if dnsRQCByVCD[constants.V6GeoString][dnsRecordV6CTY] == nil {
				mcMap := make(types.TPMSI64)
				dnsRQCByVCD[constants.V6GeoString][dnsRecordV6CTY] = mcMap
			}
			dnsRQCByVCD[constants.V6GeoString][dnsRecordV6CTY][variables.DNSDateSpec] += dnsRecordTimes
			dnsRQCByVCD[constants.V6GeoString][dnsRecordV6CTY][constants.TotalTimesString] += dnsRecordTimes
			dnsRQCByVCD[constants.V6GeoString][constants.TotalTimesString][variables.DNSDateSpec] += dnsRecordTimes
			dnsRQCByVCD[constants.V6GeoString][constants.TotalTimesString][constants.TotalTimesString] += dnsRecordTimes
		}
		// v4地理-国家是否存在
		if dnsRecordV4CTY != "null" {
			if dnsRQCByVCD[constants.V4GeoString][dnsRecordV4CTY] == nil {
				mcMap := make(types.TPMSI64)
				dnsRQCByVCD[constants.V4GeoString][dnsRecordV4CTY] = mcMap
			}
			dnsRQCByVCD[constants.V4GeoString][dnsRecordV4CTY][variables.DNSDateSpec] += dnsRecordTimes
			dnsRQCByVCD[constants.V4GeoString][dnsRecordV4CTY][constants.TotalTimesString] += dnsRecordTimes
			dnsRQCByVCD[constants.V4GeoString][constants.TotalTimesString][variables.DNSDateSpec] += dnsRecordTimes
			dnsRQCByVCD[constants.V4GeoString][constants.TotalTimesString][constants.TotalTimesString] += dnsRecordTimes
		}
	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
	util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))

	// 增加v46添加各自独有的国家
	for country, _ := range dnsRQCByVCD[constants.V4GeoString] {
		if dnsRQCByVCD[constants.V6GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			dnsRQCByVCD[constants.V6GeoString][country] = tempMap
			dnsRQCByVCD[constants.V6GeoString][country][variables.DNSDateSpec] = 0
			dnsRQCByVCD[constants.V6GeoString][country][constants.TotalTimesString] = 0
		}
	}
	for country, _ := range dnsRQCByVCD[constants.V6GeoString] {
		if dnsRQCByVCD[constants.V4GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			dnsRQCByVCD[constants.V4GeoString][country] = tempMap
			dnsRQCByVCD[constants.V4GeoString][country][variables.DNSDateSpec] = 0
			dnsRQCByVCD[constants.V4GeoString][country][constants.TotalTimesString] = 0
		}
	}
	
	// 保存结果到JSon
	jsonBytes, err := json.Marshal(dnsRQCByVCD)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(resFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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

	util.LogRecord("Ending: " + fileName + " -> " + resFileName)
}

/*
	统计活跃域名
 */
func analyseAliveDomainByGeo(fileName string, resFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName)

	// 创建存储结构, map[v4/6](map[国家](map[月份]次数))
	var domainAliveByVCD = make(types.TPMSTPMSTPMSI64)
	// v4/v6地理是否存在
	if domainAliveByVCD[constants.V4GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		domainAliveByVCD[constants.V4GeoString] = cmcMap
	}
	if domainAliveByVCD[constants.V6GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		domainAliveByVCD[constants.V6GeoString] = cmcMap
	}
	// 添加总计国家
	if domainAliveByVCD[constants.V4GeoString][constants.TotalTimesString] == nil {
		mcMap := make(types.TPMSI64)
		domainAliveByVCD[constants.V4GeoString][constants.TotalTimesString] = mcMap
	}
	if domainAliveByVCD[constants.V6GeoString][constants.TotalTimesString] == nil {
		mcMap := make(types.TPMSI64)
		domainAliveByVCD[constants.V6GeoString][constants.TotalTimesString] = mcMap
	}
	
	// 打开文件
	srcFile, eO := os.Open(fileName)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
		os.Exit(1)
	}
	defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

	inFile := bufio.NewReader(srcFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	fileLines := util.GetLines(fileName)

	if fileLines == 0 {
		util.LogRecord(fmt.Sprintf("%s is null, no need to Analyse.", fileName))
		return
	}

	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		dnsRecordBytes, _, e := inFile.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		dnsRecord := string(dnsRecordBytes)
		dnsRecordList := strings.Split(dnsRecord, "\t")

		dnsRecordV6CTY := strings.Split(dnsRecordList[constants.GeoUDV6GIndex], ";")[constants.MMCNNameIndex] // 中文国家名
		dnsRecordV4CTY := strings.Split(dnsRecordList[constants.GeoUDV4GIndex], ";")[constants.MMCNNameIndex] // 中文国家名

		// v6地理-国家是否存在
		if dnsRecordV6CTY != "null" {
			if domainAliveByVCD[constants.V6GeoString][dnsRecordV6CTY] == nil {
				tempMap := make(types.TPMSI64)
				domainAliveByVCD[constants.V6GeoString][dnsRecordV6CTY] = tempMap
			}
			domainAliveByVCD[constants.V6GeoString][dnsRecordV6CTY][variables.DNSDateSpec]++
			domainAliveByVCD[constants.V6GeoString][dnsRecordV6CTY][constants.TotalTimesString]++
			domainAliveByVCD[constants.V6GeoString][constants.TotalTimesString][variables.DNSDateSpec]++
			domainAliveByVCD[constants.V6GeoString][constants.TotalTimesString][constants.TotalTimesString]++
		}
		// v4地理-国家是否存在
		if dnsRecordV4CTY != "null" {
			if domainAliveByVCD[constants.V4GeoString][dnsRecordV4CTY] == nil {
				tempMap := make(types.TPMSI64)
				domainAliveByVCD[constants.V4GeoString][dnsRecordV4CTY] = tempMap
			}
			domainAliveByVCD[constants.V4GeoString][dnsRecordV4CTY][variables.DNSDateSpec]++
			domainAliveByVCD[constants.V4GeoString][dnsRecordV4CTY][constants.TotalTimesString]++
			domainAliveByVCD[constants.V4GeoString][constants.TotalTimesString][variables.DNSDateSpec]++
			domainAliveByVCD[constants.V4GeoString][constants.TotalTimesString][constants.TotalTimesString]++
		}
	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
	util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))

	// 为v46地理补充v64独有的国家
	for country, _ := range domainAliveByVCD[constants.V4GeoString] {
		if domainAliveByVCD[constants.V6GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			domainAliveByVCD[constants.V6GeoString][country] = tempMap
			domainAliveByVCD[constants.V6GeoString][country][variables.DNSDateSpec] = 0
			domainAliveByVCD[constants.V6GeoString][country][constants.TotalTimesString] = 0
		}
	}
	for country, _ := range domainAliveByVCD[constants.V6GeoString] {
		if domainAliveByVCD[constants.V4GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			domainAliveByVCD[constants.V4GeoString][country] = tempMap
			domainAliveByVCD[constants.V4GeoString][country][variables.DNSDateSpec] = 0
			domainAliveByVCD[constants.V4GeoString][country][constants.TotalTimesString] = 0
		}
	}
	
	// 保存结果到JSon
	jsonBytes, err := json.Marshal(domainAliveByVCD)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(resFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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

	util.LogRecord("Ending: " + fileName + " -> " + resFileName)
}

/*
	统计活跃IPv6
 */
func analyseAliveIPv6ByGeo(fileName string, resFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName)

	// 创建存储结构, map[v4/6](map[国家](map[月份]次数))
	var ipv6AliveByVCD = make(types.TPMSTPMSTPMSI64)
	// v4/v6地理是否存在
	if ipv6AliveByVCD[constants.V4GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		ipv6AliveByVCD[constants.V4GeoString] = cmcMap
	}
	if ipv6AliveByVCD[constants.V6GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		ipv6AliveByVCD[constants.V6GeoString] = cmcMap
	}
	// 添加总计国家
	if ipv6AliveByVCD[constants.V4GeoString][constants.TotalTimesString] == nil {
		mcMap := make(types.TPMSI64)
		ipv6AliveByVCD[constants.V4GeoString][constants.TotalTimesString] = mcMap
	}
	if ipv6AliveByVCD[constants.V6GeoString][constants.TotalTimesString] == nil {
		mcMap := make(types.TPMSI64)
		ipv6AliveByVCD[constants.V6GeoString][constants.TotalTimesString] = mcMap
	}

	// 打开文件
	srcFile, eO := os.Open(fileName)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
		os.Exit(1)
	}
	defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

	inFile := bufio.NewReader(srcFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	fileLines := util.GetLines(fileName)

	if fileLines == 0 {
		util.LogRecord(fmt.Sprintf("%s is null, no need to Analyse.", fileName))
		return
	}

	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		dnsRecordBytes, _, e := inFile.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		dnsRecord := string(dnsRecordBytes)
		dnsRecordList := strings.Split(dnsRecord, "\t")

		dnsRecordV6CTY := strings.Split(dnsRecordList[constants.GeoUIV6GIndex], ";")[constants.MMCNNameIndex] // 中文国家名
		dnsRecordV4CTY := strings.Split(dnsRecordList[constants.GeoUIV4GIndex], ";")[constants.MMCNNameIndex] // 中文国家名

		// v6地理-国家是否存在
		if dnsRecordV6CTY != "null" {
			if ipv6AliveByVCD[constants.V6GeoString][dnsRecordV6CTY] == nil {
				tempMap := make(types.TPMSI64)
				ipv6AliveByVCD[constants.V6GeoString][dnsRecordV6CTY] = tempMap
			}
			ipv6AliveByVCD[constants.V6GeoString][dnsRecordV6CTY][variables.DNSDateSpec]++
			ipv6AliveByVCD[constants.V6GeoString][dnsRecordV6CTY][constants.TotalTimesString]++
			ipv6AliveByVCD[constants.V6GeoString][constants.TotalTimesString][variables.DNSDateSpec]++
			ipv6AliveByVCD[constants.V6GeoString][constants.TotalTimesString][constants.TotalTimesString]++
		}
		// v4地理-国家是否存在
		if dnsRecordV4CTY != "null" {
			if ipv6AliveByVCD[constants.V4GeoString][dnsRecordV4CTY] == nil {
				tempMap := make(types.TPMSI64)
				ipv6AliveByVCD[constants.V4GeoString][dnsRecordV4CTY] = tempMap
			}
			ipv6AliveByVCD[constants.V4GeoString][dnsRecordV4CTY][variables.DNSDateSpec]++
			ipv6AliveByVCD[constants.V4GeoString][dnsRecordV4CTY][constants.TotalTimesString]++
			ipv6AliveByVCD[constants.V4GeoString][constants.TotalTimesString][variables.DNSDateSpec]++
			ipv6AliveByVCD[constants.V4GeoString][constants.TotalTimesString][constants.TotalTimesString]++
		}
	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
	util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))

	// 为v46地理补充v64独有的国家
	for country, _ := range ipv6AliveByVCD[constants.V4GeoString] {
		if ipv6AliveByVCD[constants.V6GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			ipv6AliveByVCD[constants.V6GeoString][country] = tempMap
			ipv6AliveByVCD[constants.V6GeoString][country][variables.DNSDateSpec] = 0
			ipv6AliveByVCD[constants.V6GeoString][country][constants.TotalTimesString] = 0
		}
	}
	for country, _ := range ipv6AliveByVCD[constants.V6GeoString] {
		if ipv6AliveByVCD[constants.V4GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			ipv6AliveByVCD[constants.V4GeoString][country] = tempMap
			ipv6AliveByVCD[constants.V4GeoString][country][variables.DNSDateSpec] = 0
			ipv6AliveByVCD[constants.V4GeoString][country][constants.TotalTimesString] = 0
		}
	}
	
	// 保存结果到JSon
	jsonBytes, err := json.Marshal(ipv6AliveByVCD)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(resFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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
	util.LogRecord("Ending: " + fileName + " -> " + resFileName)
}

/*
	统计活跃SLD
 */
func analyseAliveSLDByGeo(v6UniqSLD string, v4UniqSLD string, resFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + v6UniqSLD + " && " + v4UniqSLD)

	// 创建存储结构, map[v4/6](map[国家](map[月份]次数))
	var sldAliveByVCD = make(types.TPMSTPMSTPMSI64)
	// v4/v6地理是否存在
	if sldAliveByVCD[constants.V4GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		sldAliveByVCD[constants.V4GeoString] = cmcMap
	}
	if sldAliveByVCD[constants.V6GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		sldAliveByVCD[constants.V6GeoString] = cmcMap
	}
	// 添加总计国家
	if sldAliveByVCD[constants.V4GeoString][constants.TotalTimesString] == nil {
		mcMap := make(types.TPMSI64)
		sldAliveByVCD[constants.V4GeoString][constants.TotalTimesString] = mcMap
	}
	if sldAliveByVCD[constants.V6GeoString][constants.TotalTimesString] == nil {
		mcMap := make(types.TPMSI64)
		sldAliveByVCD[constants.V6GeoString][constants.TotalTimesString] = mcMap
	}

	// v6地理
	{
		// 打开文件
		srcFile, eO := os.Open(v6UniqSLD)
		if eO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
			os.Exit(1)
		}
		//defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

		inFile := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(v6UniqSLD)

		if fileLines == 0 {
			util.LogRecord(fmt.Sprintf("%s is null, no need to Analyse.", v6UniqSLD))
			return
		}

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := inFile.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")

			dnsRecordV6CTY := strings.Split(dnsRecordList[constants.V6GeoUSV6GIndex], ";")[constants.MMCNNameIndex] // 中文国家名

			// v6地理-国家是否存在
			if dnsRecordV6CTY != "null" {
				if sldAliveByVCD[constants.V6GeoString][dnsRecordV6CTY] == nil {
					tempMap := make(types.TPMSI64)
					sldAliveByVCD[constants.V6GeoString][dnsRecordV6CTY] = tempMap
				}
				sldAliveByVCD[constants.V6GeoString][dnsRecordV6CTY][variables.DNSDateSpec]++
				sldAliveByVCD[constants.V6GeoString][dnsRecordV6CTY][constants.TotalTimesString]++
				sldAliveByVCD[constants.V6GeoString][constants.TotalTimesString][variables.DNSDateSpec]++
				sldAliveByVCD[constants.V6GeoString][constants.TotalTimesString][constants.TotalTimesString]++
			}
		}
		srcFile.Close()
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	}

	// v4地理
	{
		// 打开文件
		srcFile, eO := os.Open(v4UniqSLD)
		if eO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
			os.Exit(1)
		}
		defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

		inFile := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(v4UniqSLD)

		if fileLines == 0 {
			util.LogRecord(fmt.Sprintf("%s is null, no need to Analyse.", v6UniqSLD))
			return
		}

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := inFile.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")

			dnsRecordV4CTY := strings.Split(dnsRecordList[constants.V4GeoUSV4GIndex], ";")[constants.MMCNNameIndex] // 中文国家名

			// 国家是否存在
			if dnsRecordV4CTY != "null" {
				if sldAliveByVCD[constants.V4GeoString][dnsRecordV4CTY] == nil {
					tempMap := make(types.TPMSI64)
					sldAliveByVCD[constants.V4GeoString][dnsRecordV4CTY] = tempMap
				}
				sldAliveByVCD[constants.V4GeoString][dnsRecordV4CTY][variables.DNSDateSpec]++
				sldAliveByVCD[constants.V4GeoString][dnsRecordV4CTY][constants.TotalTimesString]++
				sldAliveByVCD[constants.V4GeoString][constants.TotalTimesString][variables.DNSDateSpec]++
				sldAliveByVCD[constants.V4GeoString][constants.TotalTimesString][constants.TotalTimesString]++
			}
		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	}

	// 为v46地理补充v64独有的国家
	for country, _ := range sldAliveByVCD[constants.V4GeoString] {
		if sldAliveByVCD[constants.V6GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			sldAliveByVCD[constants.V6GeoString][country] = tempMap
			sldAliveByVCD[constants.V6GeoString][country][variables.DNSDateSpec] = 0
			sldAliveByVCD[constants.V6GeoString][country][constants.TotalTimesString] = 0
		}
	}
	for country, _ := range sldAliveByVCD[constants.V6GeoString] {
		if sldAliveByVCD[constants.V4GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			sldAliveByVCD[constants.V4GeoString][country] = tempMap
			sldAliveByVCD[constants.V4GeoString][country][variables.DNSDateSpec] = 0
			sldAliveByVCD[constants.V4GeoString][country][constants.TotalTimesString] = 0
		}
	}
	
	// 保存结果到JSon
	jsonBytes, err := json.Marshal(sldAliveByVCD)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(resFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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


	util.LogRecord("Ending: " + v6UniqSLD + " && " + v4UniqSLD + " -> " + resFileName)
}

/*
	统计TLD请求次数
 */
func analyseTLDRequestTimes(fileName string, resFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName)

	// 打开文件
	srcFile, eO := os.Open(fileName)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
		os.Exit(1)
	}
	defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

	inFile := bufio.NewReader(srcFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	fileLines := util.GetLines(fileName)
	// 创建存储结构, [](sld, count)
	var tldRQTList = make(types.TCList, fileLines)

	if fileLines == 0 {
		util.LogRecord(fmt.Sprintf("%s is null, no need to Analyse.", fileName))
		return
	}

	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		dnsRecordBytes, _, e := inFile.ReadLine()
		if e == io.EOF {
			break
		}
		dnsRecord := string(dnsRecordBytes)
		dnsRecordList := strings.Split(dnsRecord, "\t")
		dnsTLD := dnsRecordList[constants.UTTLDIndex]
		dnsTLDCount, _ := strconv.ParseInt(dnsRecordList[constants.UTCountIndex], 10, 64)
		tldRQTList[readedTotal] = types.TC{dnsTLD, dnsTLDCount}
		readedCount++
		readedTotal++
	}
	// 降序排序
	sort.Sort(sort.Reverse(tldRQTList))
	//fmt.Println(tldRQTList)


	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
	util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))

	// 提取topN
	var topN int64 = 0
	if int64(fileLines) < variables.TopNDomains {
		topN = int64(fileLines)
	} else {
		topN = variables.TopNDomains
	}
	var tldRQTMap = make(types.TPMSI64)
	var i int64
	for i = 0; i < topN; i++ {
		tldRQTMap[tldRQTList[i].TLD] = tldRQTList[i].Count
	}

	// 保存结果到JSon
	jsonBytes, err := json.Marshal(tldRQTMap)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(resFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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

	util.LogRecord("Ending: " + fileName + " -> " + resFileName)
}

/*
	统计SLD请求次数
 */
func analyseSLDRequestTimesByGeo(v6UniqSLD string, v4UniqSLD string, resFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + v6UniqSLD + " && " + v4UniqSLD)

	// 创建存储结构, map[v4/6](map[国家](map[月份]次数))
	var sldTimesByVCD = make(types.TPMSTPMSTPMSI64)
	// v4/v6地理是否存在
	if sldTimesByVCD[constants.V4GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		sldTimesByVCD[constants.V4GeoString] = cmcMap
	}
	if sldTimesByVCD[constants.V6GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		sldTimesByVCD[constants.V6GeoString] = cmcMap
	}

	// 创建输出结构, map[v4/6](map[国家](map[月份]次数))
	var JsonSLDTimesByVCD = make(types.TPMSTPMSTPMSI64)
	// v4/v6地理是否存在
	if JsonSLDTimesByVCD[constants.V4GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		JsonSLDTimesByVCD[constants.V4GeoString] = cmcMap
	}
	if JsonSLDTimesByVCD[constants.V6GeoString] == nil {
		cmcMap := make(types.TPMSTPMSI64)
		JsonSLDTimesByVCD[constants.V6GeoString] = cmcMap
	}

	// v6地理
	{
		// 打开文件
		srcFile, eO := os.Open(v6UniqSLD)
		if eO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
			os.Exit(1)
		}
		//defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

		inFile := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(v6UniqSLD)

		if fileLines == 0 {
			util.LogRecord(fmt.Sprintf("%s is null, no need to Analyse.", v6UniqSLD))
			return
		}

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := inFile.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")

			dnsRecordV6CTY := strings.Split(dnsRecordList[constants.V6GeoUSV6GIndex], ";")[constants.MMCNNameIndex] // 中文国家名

			// v6地理-国家是否存在
			if dnsRecordV6CTY != "null" {
				if sldTimesByVCD[constants.V6GeoString][dnsRecordV6CTY] == nil {
					tempMap := make(types.TPMSI64)
					sldTimesByVCD[constants.V6GeoString][dnsRecordV6CTY] = tempMap
				}
				dnsRecordV6Count, _ := strconv.ParseInt(dnsRecordList[constants.V6GeoUSCountIndex], 10, 64)
				dnsRecordV6SLD := dnsRecordList[constants.V6GeoUSSLDIndex]
				sldTimesByVCD[constants.V6GeoString][dnsRecordV6CTY][dnsRecordV6SLD] += dnsRecordV6Count
				sldTimesByVCD[constants.V6GeoString][dnsRecordV6CTY][constants.TotalTimesString] += dnsRecordV6Count
				if sldTimesByVCD[constants.V6GeoString][constants.TotalTimesString] == nil {
					tempMap := make(types.TPMSI64)
					sldTimesByVCD[constants.V6GeoString][constants.TotalTimesString] = tempMap
				}
				sldTimesByVCD[constants.V6GeoString][constants.TotalTimesString][dnsRecordV6SLD] += dnsRecordV6Count
				sldTimesByVCD[constants.V6GeoString][constants.TotalTimesString][constants.TotalTimesString] += dnsRecordV6Count
			}
		}
		srcFile.Close()

		// 存储到json数据
		for country, scMap := range sldTimesByVCD[constants.V6GeoString] {
			scMapLen := len(scMap)
			scList := make(types.SCList, scMapLen)
			i := 0
			for sld, count := range scMap {
				scList[i] = types.SC{sld, count}
				i++
			}
			// 降序排序
			sort.Sort(sort.Reverse(scList))
			// 提取topN
			if JsonSLDTimesByVCD[constants.V6GeoString][country] == nil {
				tempMap := make(types.TPMSI64)
				JsonSLDTimesByVCD[constants.V6GeoString][country] = tempMap
			}
			topN := 0
			if scMapLen < int(variables.TopNDomains) {
				topN = scMapLen
			} else {
				topN = int(variables.TopNDomains)
			}
			for i = 0; i < topN; i++ {
				JsonSLDTimesByVCD[constants.V6GeoString][country][scList[i].SLD] = scList[i].Count
			}
		}

		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	}

	// v4地理
	{
		// 打开文件
		srcFile, eO := os.Open(v4UniqSLD)
		if eO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
			os.Exit(1)
		}
		defer srcFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

		inFile := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(v4UniqSLD)

		if fileLines == 0 {
			util.LogRecord(fmt.Sprintf("%s is null, no need to Analyse.", v6UniqSLD))
			return
		}

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := inFile.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")

			dnsRecordV4CTY := strings.Split(dnsRecordList[constants.V4GeoUSV4GIndex], ";")[constants.MMCNNameIndex] // 中文国家名

			// v4地理-国家是否存在
			if dnsRecordV4CTY != "null" {
				if sldTimesByVCD[constants.V4GeoString][dnsRecordV4CTY] == nil {
					tempMap := make(types.TPMSI64)
					sldTimesByVCD[constants.V4GeoString][dnsRecordV4CTY] = tempMap
				}
				dnsRecordV4Count, _ := strconv.ParseInt(dnsRecordList[constants.V4GeoUSCountIndex], 10, 64)
				dnsRecordV4SLD := dnsRecordList[constants.V4GeoUSSLDIndex]
				sldTimesByVCD[constants.V4GeoString][dnsRecordV4CTY][dnsRecordV4SLD] += dnsRecordV4Count
				sldTimesByVCD[constants.V4GeoString][dnsRecordV4CTY][constants.TotalTimesString] += dnsRecordV4Count
				if sldTimesByVCD[constants.V4GeoString][constants.TotalTimesString] == nil {
					tempMap := make(types.TPMSI64)
					sldTimesByVCD[constants.V4GeoString][constants.TotalTimesString] = tempMap
				}
				sldTimesByVCD[constants.V4GeoString][constants.TotalTimesString][dnsRecordV4SLD] += dnsRecordV4Count
				sldTimesByVCD[constants.V4GeoString][constants.TotalTimesString][constants.TotalTimesString] += dnsRecordV4Count
			}
		}

		// 存储到json数据
		for country, scMap := range sldTimesByVCD[constants.V4GeoString] {
			scMapLen := len(scMap)
			scList := make(types.SCList, scMapLen)
			i := 0
			for sld, count := range scMap {
				scList[i] = types.SC{sld, count}
				i++
			}
			// 降序排序
			sort.Sort(sort.Reverse(scList))
			// 提取topN
			if JsonSLDTimesByVCD[constants.V4GeoString][country] == nil {
				tempMap := make(types.TPMSI64)
				JsonSLDTimesByVCD[constants.V4GeoString][country] = tempMap
			}
			topN := 0
			if scMapLen < int(variables.TopNDomains) {
				topN = scMapLen
			} else {
				topN = int(variables.TopNDomains)
			}
			for i = 0; i < topN; i++ {
				JsonSLDTimesByVCD[constants.V4GeoString][country][scList[i].SLD] = scList[i].Count
			}
		}

		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	}

	// 为v46地理补充v64独有的国家
	for country, _ := range JsonSLDTimesByVCD[constants.V4GeoString] {
		if JsonSLDTimesByVCD[constants.V6GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			JsonSLDTimesByVCD[constants.V6GeoString][country] = tempMap
			JsonSLDTimesByVCD[constants.V6GeoString][country][constants.TotalTimesString] = 0
		}
	}
	for country, _ := range JsonSLDTimesByVCD[constants.V6GeoString] {
		if JsonSLDTimesByVCD[constants.V4GeoString][country] == nil {
			tempMap := make(types.TPMSI64)
			JsonSLDTimesByVCD[constants.V4GeoString][country] = tempMap
			JsonSLDTimesByVCD[constants.V4GeoString][country][constants.TotalTimesString] = 0
		}
	}
	
	// 保存结果到JSon
	jsonBytes, err := json.Marshal(JsonSLDTimesByVCD)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(resFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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


	util.LogRecord("Ending: " + v6UniqSLD + " && " + v4UniqSLD + " -> " + resFileName)
}
