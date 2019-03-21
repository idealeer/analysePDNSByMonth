/*
@File : analyseASN.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-20 14:36
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
	"strings"
	"time"
)

/*
	获得指定国家的ASN及域名国内外分布
 */
func getSpecCountryASNAndGeo(){
	ggetSpecCountryASNAndGeo(variables.ASNCountrys, variables.RecordHisDir, variables.ASNDateSpec)
}

/*
	获得指定国家的ASN及域名国内外分布
 */
func ggetSpecCountryASNAndGeo(countrys string, recordFolder string, dateSpec string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + recordFolder + "&" + countrys + " -> " + recordFolder + "result-" + dateSpec + "/" + countrys + "/" + constants.ASNCountFN + " & " + constants.DISFNString + " & " + constants.ASNHI4CountFN)

	// 创建文件夹准备
	for _, cty := range strings.Split(countrys, ",") {

		var uniqDomainMap = make(types.TPMSS)    		// 去重域名字典
		var uniqDomainHurriMap = make(types.TPMSS)    	// 使用飓风的去重域名字典
		var asnCountMap = make(types.TPMSI64)    		// asnMap
		var disCountMap = make(types.TPMSI64)    		// 域名国内外分布
		var asnHI4CountMap = make(types.TPMSI64) 		// 使用飓风v6地址的国内域名IPv4-ASN分布

		var asnWritter *bufio.Writer					// asnWritter
		var disWritter *bufio.Writer					// 域名国内外分布Writter
		var asnHI4Writter *bufio.Writer					// 飓风v6地址的国内域名IPv4-ASN分布Writter

		// 创建国家文件夹
		ctyFolder := recordFolder + constants.DNSTempFolder + "-" + variables.DNSDateSpec + string(os.PathSeparator) + cty + string(os.PathSeparator)

		// 创建ASN写出变量
		asnFN := ctyFolder + constants.ASNCountFN + "." + constants.ASNFileExtion
		fw1, err1 := os.OpenFile(asnFN, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw1.Close()
		if err1 != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err1.Error()))
			os.Exit(1)
		}
		asnWritter = bufio.NewWriter(fw1) // 创建新的 Writer 对象

		// 创建域名国内外分布写出变量
		disFN := ctyFolder + constants.DISFNString + "." + constants.DISFileExtion
		fw2, err2 := os.OpenFile(disFN, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw2.Close()
		if err2 != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err2.Error()))
			os.Exit(1)
		}
		disWritter = bufio.NewWriter(fw2) // 创建新的 Writer 对象

		// 创建ASN-飓风-国内v4写出变量
		asnHI4FN := ctyFolder + constants.ASNHI4CountFN + "." + constants.ASNFileExtion
		fw3, err3 := os.OpenFile(asnHI4FN, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw3.Close()
		if err3 != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err3.Error()))
			os.Exit(1)
		}
		asnHI4Writter = bufio.NewWriter(fw3) // 创建新的 Writer 对象

		// 打开记录文件
		recordFN := ctyFolder + constants.ScanRecordString + "." + constants.ScanFileExtion
		srcFile, err := os.Open(recordFN)
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		defer srcFile.Close()	// 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			lineBytes, _, eR := br.ReadLine()
			if eR == io.EOF {
				break
			}
			readedCount++
			readedTotal++

			lineString := string(lineBytes)
			dnsRecordList := strings.Split(lineString, "\t")
			dnsRecordDomain := dnsRecordList[constants.GeoDomainIndex]
			dnsRecordV6Geo := dnsRecordList[constants.GeoV6GIndex] // v6地理

			// 域名国内外分布统计
			disCountMap[constants.TotalTimesString] ++
			// 国内域名
			if dnsRecordV6Geo == cty {
				// 高校域名
				if strings.HasSuffix(dnsRecordDomain, constants.DISEDUCN) {
					disCountMap[constants.DISCollegeInland] ++
				} else { // 非高校域名
					disCountMap[constants.DISNotCollegeInland] ++
				}
			} else { // 国外域名
				// 高校域名
				if strings.HasSuffix(dnsRecordDomain, constants.DISEDUCN) {
					disCountMap[constants.DISCollegeForeign] ++
				} else { // 非高校域名
					disCountMap[constants.DISNotCollegeForeign] ++
				}
			}

			// 域名对应ASN统计、飓风统计
			if !strings.HasSuffix(dnsRecordDomain, constants.DISEDUCN) {
				if _, ok := uniqDomainMap[dnsRecordDomain]; !ok {
					uniqDomainMap[dnsRecordDomain] = ""
					dnsRecordIPv6 := strings.Split(strings.TrimRight(dnsRecordList[constants.GeoIPv6Index], ";"), ";")[0]

					// 获得ASN
					asnNum, asnString := util.GetIPASNByMM(dnsRecordIPv6, variables.MaxMindASNReader)

					// 不存在不计数
					if asnNum == constants.ASNNullNumber {
						continue
					}

					// 次数加一
					asnCountMap[asnString] ++
					asnCountMap[constants.TotalTimesString] ++

					// 国外飓风厂商
					fmt.Println(asnNum)
					if asnNum == constants.ASNNHurricane {
						if _, ok := uniqDomainHurriMap[dnsRecordDomain]; !ok{
							uniqDomainHurriMap[dnsRecordDomain] = ""
							dnsRecordIPv4 := strings.Split(strings.TrimRight(dnsRecordList[constants.GeoIPv4Index], ";"), ";")[0]
							// 获得ASN
							asnNum, asnString := util.GetIPASNByMM(dnsRecordIPv4, variables.MaxMindASNReader)

							// 不存在不计数
							if asnNum == constants.ASNNullNumber {
								continue
							}

							// 次数加一
							asnHI4CountMap[asnString] ++
							asnHI4CountMap[constants.TotalTimesString] ++
						}
					}
				}
			}
		}
		util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))

		// 保存ASN结果
		asnList := make(types.ASNCList, 0)
		for asn, c := range asnCountMap {
			asnList = append(asnList, types.ASNC{asn, c})
		}
		// 降序排序
		sort.Sort(sort.Reverse(asnList))
		// 保存结果到JSon
		asnJson, err := json.Marshal(asnList)
		_, err = asnWritter.WriteString(string(asnJson) + "\n")
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		asnWritter.Flush()

		// 保存ASN-Hurricane结果
		asnHI4List := make(types.ASNCList, 0)
		for asn, c := range asnHI4CountMap {
			asnHI4List = append(asnHI4List, types.ASNC{asn, c})
		}
		// 降序排序
		sort.Sort(sort.Reverse(asnHI4List))
		// 保存结果到JSon
		asnJson4, err := json.Marshal(asnHI4List)
		_, err = asnHI4Writter.WriteString(string(asnJson4) + "\n")
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		asnHI4Writter.Flush()

		// 保存分布结果
		disList := make(types.DisCList, 0)
		for dis, c := range disCountMap {
			disList = append(disList, types.DisC{dis, c})
		}
		// 降序排序
		sort.Sort(sort.Reverse(disList))
		// 保存结果到JSon
		disJson, err := json.Marshal(disList)
		_, err = disWritter.WriteString(string(disJson) + "\n")
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		disWritter.Flush()
	}

	util.LogRecord("Ending: " + recordFolder + "&" + countrys + " -> " + recordFolder + "temp-" + dateSpec + "/" + countrys + "/" + constants.ASNCountFN + " & " + constants.DISFNString + " & " + constants.ASNHI4CountFN)
}


/*
	获得ipASN信息
 */
func getASN(ips string) {
	ipList := strings.Split(strings.TrimRight(ips, ","), ",")
	for _, ip := range ipList {
		asnNum, asnStr := util.GetIPASNByMM(ip, variables.MaxMindASNReader)
		util.LogRecord(fmt.Sprintf("%s\t%d\t%s", ip, asnNum, asnStr))
	}
}

/*
	获得ip文件的ASN信息
 */
func getASNByFile(ipFileName string, ipASNFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + ipFileName + " & " + variables.MaxMindASNDBName + " -> " + ipASNFileName)

	// 打开文件
	dnsFile, eOOO := os.Open(ipFileName)
	if eOOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-ip-file parm]", eOOO.Error()))
		os.Exit(1)
	}
	defer dnsFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

	// 创建文件
	fw, eOO := os.OpenFile(ipASNFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw.Close()
	if eOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
		os.Exit(1)
	}
	outDNSGeoFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

	inDNSFile := bufio.NewReader(dnsFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	fileLines := util.GetLines(ipFileName)

	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		ipBytes, _, e := inDNSFile.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		ip := string(ipBytes)
		ip = strings.TrimRight(ip, "\n")
		asnNum, asnStr := util.GetIPASNByMM(ip, variables.MaxMindASNReader)

		dnsRecordNew := fmt.Sprintf("%s\t%d\t%s\n", ip, asnNum, asnStr)

		// 保存添加IPASN信息的记录
		_, eW := outDNSGeoFile.WriteString(dnsRecordNew)

		if eW != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
			os.Exit(1)
		}
		outDNSGeoFile.Flush()

	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

	util.LogRecord("Ending: " + ipFileName + " & " + variables.MaxMindASNDBName + " -> " + ipASNFileName)
}

