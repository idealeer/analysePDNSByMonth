/*
@File : analyseResult.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-15 18:54
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

func AnalyseResult() {
	timeNow := time.Now()
	util.LogRecord("Excuting: ")

	variables.JsonV6DNSTimes = GetResFileName(constants.JsonV6DNSTimes+"-By"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonV6IPv6Alive = GetResFileName(constants.JsonV6IPv6Alive+"-By"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonV6DomainAlive = GetResFileName(constants.JsonV6DomainAlive+"-By"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonV6SLDAlive = GetResFileName(constants.JsonV6SLDAlive+"-By"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonV6SLDTimes = GetResFileName(constants.JsonV6SLDTimes+"-"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonTLDTimes = GetResFileName(constants.JsonTLDTimes+"-"+variables.DNSDateSpec, constants.JsonExtion)

	// variables.D4FileName
	// variables.V6GeoFileName
	util.LogRecordSimple(time.Now().String() + "\n")

	for _, cty := range strings.Split(variables.Countrys, ",") {
		util.LogRecordSimple(variables.IsoCNNameMap[cty] + "(" + cty + ")")
		outDNSTimes(variables.JsonV6DNSTimes, cty)
		outIPv6Alive(variables.JsonV6IPv6Alive, cty)
		outDomainAlive(variables.JsonV6DomainAlive, cty)
		outSLDAlive(variables.JsonV6SLDAlive, cty)
		outSLDTimes(variables.JsonV6SLDTimes, cty)
		if cty == constants.TotalTimesString {
			outTLDTimes(variables.JsonTLDTimes, cty)
			outIpv6Times(variables.V6GeoFileName, variables.Countrys)
			outDomainTimes(variables.D4FileName, variables.Countrys, variables.V4GeoFileName)
		}
	}



	util.LogRecordSimple(time.Now().String() + "\n\n")


	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: ")
}

// 输出DNS请求次数
func outDNSTimes(fileName string, country string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + ", country: " + country)

	var nowMap = make(types.TPMSTPMSTPMSI64, 200)

	nowFile, eO0 := os.Open(fileName)
	if eO0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO0.Error()))
		os.Exit(1)
	}
	defer nowFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inNowFile := bufio.NewReader(nowFile)
	nowJsonString, eR0 := inNowFile.ReadString('\n')

	if eR0 == io.EOF || eR0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileName))
		os.Exit(1)
	}
	eU0 := json.Unmarshal([]byte(nowJsonString), &nowMap)
	if eU0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileName, eU0.Error()))
		os.Exit(1)
	}

	var total 	int64							// 总次数
	var xMStr	string							// 次数最多月
	var nMStr	string							// 次数最少月
	var xMTimes int64							// 最多月次数
	var nMTimes int64 = constants.INT64MAX		// 最少月次数

	// 统计结果，取v46平均值
	total = (nowMap[constants.V4GeoString][country][constants.TotalTimesString] + nowMap[constants.V6GeoString][country][constants.TotalTimesString]) / 2
	for m, c := range nowMap[constants.V4GeoString][country] {
		tmpMTimes := (c + nowMap[constants.V6GeoString][country][m]) / 2
		if xMTimes < tmpMTimes && m != constants.TotalTimesString{
			xMTimes = tmpMTimes
			xMStr = m
		}
		if nMTimes > tmpMTimes {
			nMTimes = tmpMTimes
			nMStr = m
		}
	}

	tal := total / constants.YYTimes								// 总量
	avgDay := total / variables.TotalDayNum / constants.YWTimes		// 平均每天数量

	avgMonth := total / variables.TotalMonthNum / constants.YWTimes	// 平均每月数量
	xmS := util.GetChineseMonth(xMStr)								// 数量最多月份
	xMT	:= xMTimes / constants.YWTimes								// 最多数量
	nMS := util.GetChineseMonth(nMStr)								// 最少数量月份
	nMT := nMTimes / constants.YWTimes								// 最少数量

	cpN := variables.CPLNum	/ constants.YYTimes						// 中国总人口
	avgPD := variables.CPLNum / constants.YWTimes / avgDay			// 人均
	country = variables.IsoCNNameMap[country]						// 英文简称转中文名

	cnN := variables.CNZNum / constants.YYTimes						// 中国总网民
	avgPM := variables.CNZNum / constants.YWTimes / avgDay			// 网民平均
	// country

	util.LogRecordSimple(fmt.Sprintf(constants.ResStrDNSTimes, tal, avgDay, avgMonth, xmS, xMT, nMS, nMT,cpN, avgPD, country, cnN, avgPM, country))

	util.LogRecord(fmt.Sprintf(constants.ResStrDNSTimes, tal, avgDay, avgMonth, xmS, xMT,nMS, nMT,cpN, avgPD, country, cnN, avgPM, country))
	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + ", country: " + country)
}

// 输出IPv6活跃数量
func outIPv6Alive(fileName string, country string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + ", country: " + country)

	var nowMap = make(types.TPMSTPMSTPMSI64, 200)

	nowFile, eO0 := os.Open(fileName)
	if eO0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO0.Error()))
		os.Exit(1)
	}
	defer nowFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inNowFile := bufio.NewReader(nowFile)
	nowJsonString, eR0 := inNowFile.ReadString('\n')

	if eR0 == io.EOF || eR0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileName))
		os.Exit(1)
	}
	eU0 := json.Unmarshal([]byte(nowJsonString), &nowMap)
	if eU0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileName, eU0.Error()))
		os.Exit(1)
	}

	var total 	int64							// 总次数
	var xMStr	string							// 次数最多月
	var nMStr	string							// 次数最少月
	var xMTimes int64							// 最多月次数
	var nMTimes int64 = constants.INT64MAX		// 最少月次数

	// 统计结果，取v46平均值
	total = (nowMap[constants.V4GeoString][country][constants.TotalTimesString] + nowMap[constants.V6GeoString][country][constants.TotalTimesString]) / 2
	for m, c := range nowMap[constants.V4GeoString][country] {
		tmpMTimes := (c + nowMap[constants.V6GeoString][country][m]) / 2
		if xMTimes < tmpMTimes && m != constants.TotalTimesString{
			xMTimes = tmpMTimes
			xMStr = m
		}
		if nMTimes > tmpMTimes {
			nMTimes = tmpMTimes
			nMStr = m
		}
	}

	tal := total / constants.YWTimes								// 总量

	avgMonth := total / variables.TotalMonthNum / constants.YWTimes	// 平均每月数量

	xmS := util.GetChineseMonth(xMStr)								// 数量最多月份
	xMT	:= xMTimes / constants.YWTimes								// 最多数量
	nMS := util.GetChineseMonth(nMStr)								// 最少数量月份
	nMT := nMTimes													// 最少数量

	util.LogRecordSimple(fmt.Sprintf(constants.ResStrIPv6Alive, tal, avgMonth, xmS, xMT, nMS, nMT))

	util.LogRecord(fmt.Sprintf(constants.ResStrIPv6Alive, tal, avgMonth, xmS, xMT, nMS, nMT))
	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + ", country: " + country)
}

// 输出域名活跃数量
func outDomainAlive(fileName string, country string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + ", country: " + country)

	var nowMap = make(types.TPMSTPMSTPMSI64, 200)

	nowFile, eO0 := os.Open(fileName)
	if eO0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO0.Error()))
		os.Exit(1)
	}
	defer nowFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inNowFile := bufio.NewReader(nowFile)
	nowJsonString, eR0 := inNowFile.ReadString('\n')

	if eR0 == io.EOF || eR0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileName))
		os.Exit(1)
	}
	eU0 := json.Unmarshal([]byte(nowJsonString), &nowMap)
	if eU0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileName, eU0.Error()))
		os.Exit(1)
	}

	var total 	int64							// 总次数
	var xMStr	string							// 次数最多月
	var nMStr	string							// 次数最少月
	var xMTimes int64							// 最多月次数
	var nMTimes int64 = constants.INT64MAX		// 最少月次数

	// 统计结果，取v46平均值
	total = (nowMap[constants.V4GeoString][country][constants.TotalTimesString] + nowMap[constants.V6GeoString][country][constants.TotalTimesString]) / 2
	for m, c := range nowMap[constants.V4GeoString][country] {
		tmpMTimes := (c + nowMap[constants.V6GeoString][country][m]) / 2
		if xMTimes < tmpMTimes && m != constants.TotalTimesString{
			xMTimes = tmpMTimes
			xMStr = m
		}
		if nMTimes > tmpMTimes {
			nMTimes = tmpMTimes
			nMStr = m
		}
	}

	tal := total / constants.YWTimes								// 总量

	avgMonth := total / variables.TotalMonthNum / constants.YWTimes	// 平均每月数量

	xmS := util.GetChineseMonth(xMStr)								// 数量最多月份
	xMT	:= xMTimes / constants.YWTimes								// 最多数量
	nMS := util.GetChineseMonth(nMStr)								// 最少数量月份
	nMT := nMTimes													// 最少数量

	util.LogRecordSimple(fmt.Sprintf(constants.ResStrDomainAlive, tal, avgMonth, xmS, xMT, nMS, nMT))

	util.LogRecord(fmt.Sprintf(constants.ResStrDomainAlive, tal, avgMonth, xmS, xMT, nMS, nMT))
	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + ", country: " + country)
}

// 输出SLD活跃数量
func outSLDAlive(fileName string, country string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + ", country: " + country)

	var nowMap = make(types.TPMSTPMSTPMSI64, 200)

	nowFile, eO0 := os.Open(fileName)
	if eO0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO0.Error()))
		os.Exit(1)
	}
	defer nowFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inNowFile := bufio.NewReader(nowFile)
	nowJsonString, eR0 := inNowFile.ReadString('\n')

	if eR0 == io.EOF || eR0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileName))
		os.Exit(1)
	}
	eU0 := json.Unmarshal([]byte(nowJsonString), &nowMap)
	if eU0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileName, eU0.Error()))
		os.Exit(1)
	}

	var total 	int64							// 总次数
	var xMStr	string							// 次数最多月
	var nMStr	string							// 次数最少月
	var xMTimes int64							// 最多月次数
	var nMTimes int64 = constants.INT64MAX		// 最少月次数

	// 统计结果，取v46平均值
	total = (nowMap[constants.V4GeoString][country][constants.TotalTimesString] + nowMap[constants.V6GeoString][country][constants.TotalTimesString]) / 2
	for m, c := range nowMap[constants.V4GeoString][country] {
		tmpMTimes := (c + nowMap[constants.V6GeoString][country][m]) / 2
		if xMTimes < tmpMTimes && m != constants.TotalTimesString{
			xMTimes = tmpMTimes
			xMStr = m
		}
		if nMTimes > tmpMTimes {
			nMTimes = tmpMTimes
			nMStr = m
		}
	}

	tal := total / constants.YWTimes								// 总量

	avgMonth := total / variables.TotalMonthNum						// 平均每月数量

	xmS := util.GetChineseMonth(xMStr)								// 数量最多月份
	xMT	:= xMTimes													// 最多数量
	nMS := util.GetChineseMonth(nMStr)								// 最少数量月份
	nMT := nMTimes													// 最少数量

	util.LogRecordSimple(fmt.Sprintf(constants.ResStrSLDAlive, tal, avgMonth, xmS, xMT, nMS, nMT))

	util.LogRecord(fmt.Sprintf(constants.ResStrSLDAlive, tal, avgMonth, xmS, xMT, nMS, nMT))
	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + ", country: " + country)
}

// 输出SLD请求次数
func outSLDTimes(fileName string, country string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + ", country: " + country)

	var nowMap = make(types.TPMSTPMSTPMSI64, 200)

	nowFile, eO0 := os.Open(fileName)
	if eO0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO0.Error()))
		os.Exit(1)
	}
	defer nowFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inNowFile := bufio.NewReader(nowFile)
	nowJsonString, eR0 := inNowFile.ReadString('\n')

	if eR0 == io.EOF || eR0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileName))
		os.Exit(1)
	}
	eU0 := json.Unmarshal([]byte(nowJsonString), &nowMap)
	if eU0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileName, eU0.Error()))
		os.Exit(1)
	}

	var total 	int64                       	// 总次数
	var xSLDStr string                       	// 次数最多月
	var nSLDStr string                       	// 次数最少月
	var xSLDTimes int64                      	// 最多月次数
	var nSLDTimes int64 = constants.INT64MAX 	// 最少月次数

	// 统计结果，取v46平均值
	total = (nowMap[constants.V4GeoString][country][constants.TotalTimesString] + nowMap[constants.V6GeoString][country][constants.TotalTimesString]) / 2
	for sld, c := range nowMap[constants.V4GeoString][country] {
		tmpMTimes := (c + nowMap[constants.V6GeoString][country][sld]) / 2
		if xSLDTimes < tmpMTimes && sld != constants.TotalTimesString{
			xSLDTimes = tmpMTimes
			xSLDStr = sld
		}
		if nSLDTimes > tmpMTimes {
			nSLDTimes = tmpMTimes
			nSLDStr = sld
		}
	}

	tal := total / constants.YYTimes								// 总量
	avgDay := total / 30 / constants.YYTimes		// 平均每天数量

	xSLDT := xSLDTimes / constants.YYTimes // 最多数量
	nSLDT := nSLDTimes / constants.YWTimes // 最少数量

	util.LogRecordSimple(fmt.Sprintf(constants.ResStrSLDTimes, util.GetChineseMonth(variables.DNSDateSpec), tal, avgDay, xSLDStr, xSLDT, nSLDStr, nSLDT))

	util.LogRecord(fmt.Sprintf(constants.ResStrSLDTimes, util.GetChineseMonth(variables.DNSDateSpec), tal, avgDay, xSLDStr, xSLDT, nSLDStr, nSLDT))
	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + ", country: " + country)
}

// 输出TLD请求次数
func outTLDTimes(fileName string, country string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + ", country: " + country)

	var nowMap = make(types.TPMSI64, 50)

	nowFile, eO0 := os.Open(fileName)
	if eO0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO0.Error()))
		os.Exit(1)
	}
	defer nowFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inNowFile := bufio.NewReader(nowFile)
	nowJsonString, eR0 := inNowFile.ReadString('\n')

	if eR0 == io.EOF || eR0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileName))
		os.Exit(1)
	}
	eU0 := json.Unmarshal([]byte(nowJsonString), &nowMap)
	if eU0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileName, eU0.Error()))
		os.Exit(1)
	}

	var total 		int64                       	// 总次数
	var xTLDStr 	string                       	// 次数最多tld
	var nTLDStr 	string                       	// 次数最少tld
	var xTLDTimes 	int64                      		// 最多tld次数
	var nTLDTimes 	int64 = constants.INT64MAX 		// 最少tld次数

	// 统计结果，取v46平均值
	for tld, c := range nowMap {
		if xTLDTimes < c {
			xTLDTimes = c
			xTLDStr = tld
		}
		if nTLDTimes > c {
			nTLDTimes = c
			nTLDStr = tld
		}
		total += c
	}

	tal := total / constants.YYTimes								// 总量
	avgDay := total / 30 / constants.YYTimes						// 平均每天数量

	xSLDT := xTLDTimes / constants.YYTimes 							// 最多数量
	nSLDT := nTLDTimes / constants.YWTimes 							// 最少数量

	util.LogRecordSimple(fmt.Sprintf(constants.ResStrTLDTimes, util.GetChineseMonth(variables.DNSDateSpec), tal, avgDay, xTLDStr, xSLDT, nTLDStr, nSLDT))

	util.LogRecord(fmt.Sprintf(constants.ResStrTLDTimes, util.GetChineseMonth(variables.DNSDateSpec), tal, avgDay, xTLDStr, xSLDT, nTLDStr, nSLDT))
	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + ", country: " + country)
}

// 输出IPv6数量
func outIpv6Times(fileName string, countryS string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + ", countrys: " + countryS)

	var nowMap = make(types.TPMSI64)
	var geoMap = make(types.TPMSS)

	// 分析国家
	for _, cty := range strings.Split(variables.Countrys, ",") {
		geoMap[cty] = variables.IsoCNNameMap[cty]
	}

	nowFile, eO0 := os.Open(fileName)
	if eO0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO0.Error()))
		os.Exit(1)
	}
	defer nowFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inNowFile := bufio.NewReader(nowFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	for {
		if readedCount % variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))
		}
		v6GeoBytes, _, e := inNowFile.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++

		v6GeoStr := string(v6GeoBytes)
		cty := strings.Split(v6GeoStr, "\t")[1]

		if _, ok := geoMap[cty]; ok {
			nowMap[cty] ++
		}
		nowMap[constants.TotalTimesString] ++
	}
	util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))

	resOut := ""

	for _, cty := range strings.Split(variables.Countrys, ",") {
		if cty == constants.TotalTimesString {
			resOut += fmt.Sprintf(constants.ResStrIPv6Times, nowMap[constants.TotalTimesString] / constants.YWTimes)
		} else {
			resOut += fmt.Sprintf(constants.ResStrCTimes, geoMap[cty], nowMap[cty] / constants.YWTimes)
		}
	}

	util.LogRecordSimple(resOut)
	util.LogRecord(resOut)

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + ", country: " + countryS)
}

// 输出域名数量
func outDomainTimes(fileName string, countryS string, v4GeoFile string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + ", countrys: " + countryS)

	var nowMap= make(types.TPMSI64)
	var geoMap= make(types.TPMSS)
	var ip4GeoMap= make(types.TPMSS, constants.MapAllocLen)	// 用于查找地理

	var readedCount uint64 = 0
	var readedTotal uint64 = 0

	// 分析国家字典
	for _, cty := range strings.Split(variables.Countrys, ",") {
		geoMap[cty] = variables.IsoCNNameMap[cty]
	}

	// 初始化ipv4地理字典
	ipFile, eO := os.Open(v4GeoFile)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
		os.Exit(1)
	}
	defer ipFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inIPFile := bufio.NewReader(ipFile)
	fileLines := util.GetLines(variables.V4GeoFileName)
	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("Create IPv4GeoMap, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		ipGeoBytes, _, eR := inIPFile.ReadLine()
		if eR == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		ipGeo := string(ipGeoBytes)
		ipGeoList := strings.Split(ipGeo, "\t")
		ip := ipGeoList[0]
		if _, ok := ip4GeoMap[ip]; !ok {
			ip4GeoMap[ip] = ipGeoList[1]
		}
	}
	util.LogRecord(fmt.Sprintf("create IPv4GeoMap, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
	util.LogRecord(fmt.Sprintf("create IPv4GeoMap, total: %d, cost: %ds", fileLines, time.Now().Sub(timeNow)/time.Second))

	// 遍历域名文件
	nowFile, eO0 := os.Open(fileName)
	if eO0 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO0.Error()))
		os.Exit(1)
	}
	defer nowFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inNowFile := bufio.NewReader(nowFile)

	readedCount = 0
	readedTotal = 0

	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		dv4Bytes, _, e := inNowFile.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++

		dv4Str := string(dv4Bytes)
		v4 := strings.Split(strings.Split(dv4Str, "\t")[1], ";")[0]
		v4Geo := ip4GeoMap[v4]

		if _, ok := geoMap[v4Geo]; ok {
			nowMap[v4Geo] ++
		}
		nowMap[constants.TotalTimesString] ++
	}
	util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))

	resOut := ""

	for _, cty := range strings.Split(variables.Countrys, ",") {
		if cty == constants.TotalTimesString {
			resOut += fmt.Sprintf(constants.ResStrDomainTimes, nowMap[constants.TotalTimesString]/constants.YWTimes)
		} else {
			resOut += fmt.Sprintf(constants.ResStrCTimes, geoMap[cty], nowMap[cty]/constants.YWTimes)
		}
	}

	util.LogRecordSimple(resOut)
	util.LogRecord(resOut)

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow)/time.Second))
	util.LogRecord("Ending: " + fileName + ", country: " + countryS)
}

