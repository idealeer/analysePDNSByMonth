/*
@File : outResult.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-18 16:35
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
	"time"
)

func OutShowResult() {
	timeNow := time.Now()
	util.LogRecord("Excuting: ")

	// 获得结果文件
	variables.JsonV6DNSTimes = GetResFileName(constants.JsonV6DNSTimes+"-By"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonV6IPv6Alive = GetResFileName(constants.JsonV6IPv6Alive+"-By"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonV6DomainAlive = GetResFileName(constants.JsonV6DomainAlive+"-By"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonV6SLDAlive = GetResFileName(constants.JsonV6SLDAlive+"-By"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonV6SLDTimes = GetResFileName(constants.JsonV6SLDTimes+"-"+variables.DNSDateSpec, constants.JsonExtion)
	variables.JsonTLDTimes = GetResFileName(constants.JsonTLDTimes+"-"+variables.DNSDateSpec, constants.JsonExtion)

	// 输出DNS请求次数v46文件
	OutTimesAndAliveResult(variables.JsonV6DNSTimes, GetShowV4FileName(constants.ShowDNSTimes, constants.ShowFileExtion), GetShowV6FileName(constants.ShowDNSTimes, constants.ShowFileExtion))

	// 输出活跃IPv6-v46文件
	OutTimesAndAliveResult(variables.JsonV6IPv6Alive, GetShowV4FileName(constants.ShowIPv6FName, constants.ShowFileExtion), GetShowV6FileName(constants.ShowIPv6FName, constants.ShowFileExtion))

	// 输出活跃域名-v46文件
	OutTimesAndAliveResult(variables.JsonV6DomainAlive, GetShowV4FileName(constants.ShowDomainFName, constants.ShowFileExtion), GetShowV6FileName(constants.ShowDomainFName, constants.ShowFileExtion))

	// 输出活跃SLD-v46文件
	OutTimesAndAliveResult(variables.JsonV6SLDAlive, GetShowV4FileName(constants.ShowSLDFName, constants.ShowFileExtion), GetShowV6FileName(constants.ShowSLDFName, constants.ShowFileExtion))

	// 输出TLD次数
	OutTLDResult(variables.JsonTLDTimes, GetShowV4FileName(constants.TopNTLD, constants.ShowFileExtion), GetShowV6FileName(constants.TopNTLD, constants.ShowFileExtion))

	// 输出SLD次数
	OutSLDResult(variables.JsonV6SLDTimes, GetShowV4FileName(constants.TopNSLD, constants.ShowFileExtion), GetShowV6FileName(constants.TopNSLD, constants.ShowFileExtion), GetShowV4FileName(constants.TopNSLDTotal, constants.ShowFileExtion), GetShowV6FileName(constants.TopNSLDTotal, constants.ShowFileExtion))

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: ")
}

/*
	输出DNS次数、活跃次数的V4、6文件
 */
func OutTimesAndAliveResult(fileTger string, fileV4 string, fileV6 string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileTger + " -> " + fileV4 + " & " + fileV6)

	// 结果Map
	var v46Map = make(types.TPMSTPMSTPMSI64, 200)		// v46地理Map
	//var v4Map = make(types.TPMSTPMSI64, 200)			// v4地理Map
	//var v6Map = make(types.TPMSTPMSI64, 200)			// v6地理Map


	// 读入先前Json结果，构建字典
	beforeFile, eO := os.Open(fileTger)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s, no %s file found", eO.Error(), fileTger))
		return
	}
	defer beforeFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inBeforeFile := bufio.NewReader(beforeFile)

	beforeJsonString, eR := inBeforeFile.ReadString('\n')
	if eR == io.EOF || eR != nil{
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileTger))
		os.Exit(1)
	}

	eU := json.Unmarshal([]byte(beforeJsonString), &v46Map)
	if eU != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileTger, eU.Error()))
		os.Exit(1)
	}

	// 保存v4地理结果到JSon
	jsonBytes, err := json.Marshal(v46Map[constants.V4GeoString])
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(fileV4, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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

	// 保存v6地理结果到JSon
	jsonBytes6, err6 := json.Marshal(v46Map[constants.V6GeoString])
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}

	fw6, err6 := os.OpenFile(fileV6, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw.Close()
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	outWFile6 := bufio.NewWriter(fw6) // 创建新的 Writer 对象
	_, err6 = outWFile6.WriteString(string(jsonBytes6) + "\n")
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	outWFile6.Flush()

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileTger + " -> " + fileV4 + " & " + fileV6)
}

/*
	输出TopN-TLD的V4、6文件
 */
func OutTLDResult(fileTger string, fileV4 string, fileV6 string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileTger + " -> " + fileV4 + " & " + fileV6)

	// 结果Map
	var tldMap = make(types.TPMSI64, variables.TopNDomains)		// tld:次数字典

	// 读入先前Json结果，构建字典
	beforeFile, eO := os.Open(fileTger)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s, no %s file found", eO.Error(), fileTger))
		return
	}
	defer beforeFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inBeforeFile := bufio.NewReader(beforeFile)

	beforeJsonString, eR := inBeforeFile.ReadString('\n')
	if eR == io.EOF || eR != nil{
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileTger))
		os.Exit(1)
	}

	eU := json.Unmarshal([]byte(beforeJsonString), &tldMap)
	if eU != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileTger, eU.Error()))
		os.Exit(1)
	}

	// 输出json
	var tldJson = make(types.DCList, 0)

	// 遍历字典
	for domain, count := range tldMap {
		tldJson = append(tldJson, types.DC{domain, count})
	}

	// 降序排序
	sort.Sort(sort.Reverse(tldJson))

	// 保存tld结果到v4-JSon
	jsonBytes, err := json.Marshal(tldJson)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}

	fw, err := os.OpenFile(fileV4, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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

	// 保存tld结果到v6-JSon
	jsonBytes6, err6 := json.Marshal(tldJson)
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}

	fw6, err6 := os.OpenFile(fileV6, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw.Close()
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	outWFile6 := bufio.NewWriter(fw6) // 创建新的 Writer 对象
	_, err6 = outWFile6.WriteString(string(jsonBytes6) + "\n")
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	outWFile6.Flush()

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileTger + " -> " + fileV4 + " & " + fileV6)
}

/*
	输出TopN-SLD的V4、6文件
 */
func OutSLDResult(fileTger string, fileV4 string, fileV6 string, fileV4Total string, fileV6Total string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileTger + " -> " + fileV4 + " & " + fileV6 + " & " + fileV4Total + " & " + fileV6Total)

	// 结果Map
	var sldV46Map = make(types.TPMSTPMSTPMSI64, 200) 			// v46地理Map

	// 读入先前Json结果，构建字典
	beforeFile, eO := os.Open(fileTger)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s, no %s file found", eO.Error(), fileTger))
		return
	}
	defer beforeFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inBeforeFile := bufio.NewReader(beforeFile)

	beforeJsonString, eR := inBeforeFile.ReadString('\n')
	if eR == io.EOF || eR != nil{
		util.LogRecord(fmt.Sprintf("Error: %s is null", fileTger))
		os.Exit(1)
	}

	eU := json.Unmarshal([]byte(beforeJsonString), &sldV46Map)
	if eU != nil {
		util.LogRecord(fmt.Sprintf("Error: %s : %s", fileTger, eU.Error()))
		os.Exit(1)
	}

	/// 输出tld-v4地理-json
	var sldV4Json = make(types.DCListMap, 200)
	for country, dcMap := range sldV46Map[constants.V4GeoString] {
		if _, ok := sldV4Json[country]; !ok {
			dcList := make(types.DCList, 0)
			sldV4Json[country] = dcList
		}
		for d, c := range dcMap {
			if d == constants.TotalTimesString {
				continue
			}
			sldV4Json[country] = append(sldV4Json[country], types.DC{d, c})
		}
		// 降序排序
		sort.Sort(sort.Reverse(sldV4Json[country]))
	}
	// 保存tld结果到v4-JSon
	jsonBytes, err := json.Marshal(sldV4Json)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	fw, err := os.OpenFile(fileV4, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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


	/// 输出tld-v6地理-json
	var sldV6Json = make(types.DCListMap, 200)
	for country, dcMap := range sldV46Map[constants.V6GeoString] {
		if _, ok := sldV6Json[country]; !ok {
			dcList := make(types.DCList, 0)
			sldV6Json[country] = dcList
		}
		for d, c := range dcMap {
			if d == constants.TotalTimesString {
				continue
			}
			sldV6Json[country] = append(sldV6Json[country], types.DC{d, c})
		}
		// 降序排序
		sort.Sort(sort.Reverse(sldV6Json[country]))
	}
	// 保存tld结果到v6-JSon
	jsonBytes6, err6 := json.Marshal(sldV6Json)
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	fw6, err6 := os.OpenFile(fileV6, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw6.Close()
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	outWFile6 := bufio.NewWriter(fw6) // 创建新的 Writer 对象
	_, err6 = outWFile6.WriteString(string(jsonBytes6) + "\n")
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	outWFile6.Flush()


	/// 输出tld-v4地理-total-json
	var tldV4TotalJson = make(types.DCList, 0)
	// 遍历字典
	for domain, count := range sldV46Map[constants.V4GeoString][constants.TotalTimesString] {
		if domain == constants.TotalTimesString {
			continue
		}
		tldV4TotalJson = append(tldV4TotalJson, types.DC{domain, count})
	}
	// 降序排序
	sort.Sort(sort.Reverse(tldV4TotalJson))
	// 保存tld结果到v4-JSon
	jsonBytes4t, err := json.Marshal(tldV4TotalJson)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	fw4t, err := os.OpenFile(fileV4Total, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw.Close()
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	outWFile4t := bufio.NewWriter(fw4t) // 创建新的 Writer 对象
	_, err = outWFile4t.WriteString(string(jsonBytes4t) + "\n")
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	outWFile4t.Flush()


	/// 输出tld-v4地理-total-json
	var tldV6TotalJson = make(types.DCList, 0)
	// 遍历字典
	for domain, count := range sldV46Map[constants.V6GeoString][constants.TotalTimesString] {
		if domain == constants.TotalTimesString {
			continue
		}
		tldV6TotalJson = append(tldV6TotalJson, types.DC{domain, count})
	}
	// 保存tld结果到v6-JSon
	jsonBytes6t, err6 := json.Marshal(tldV6TotalJson)
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	fw6t, err6 := os.OpenFile(fileV6Total, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw6t.Close()
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	outWFile6t := bufio.NewWriter(fw6t) // 创建新的 Writer 对象
	_, err6 = outWFile6t.WriteString(string(jsonBytes6t) + "\n")
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	outWFile6t.Flush()


	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileTger + " -> " + fileV4 + " & " + fileV6 + " & " + fileV4Total + " & " + fileV6Total)
}
