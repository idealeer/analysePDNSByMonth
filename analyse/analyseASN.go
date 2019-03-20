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
	util.LogRecord("Excuting: " + recordFolder + "&" + countrys + " -> " + recordFolder + "result-" + dateSpec + "/" + countrys + "/" + constants.ASNCountFN + " & " + constants.DISFNString)

	// 创建文件夹准备
	for _, cty := range strings.Split(countrys, ",") {

		var uniqDomainMap = make(types.TPMSS)        	// 每个国家的去重域名字典
		var asnWritter *bufio.Writer					// asnWritter
		var disWritter *bufio.Writer					// 域名国内外分布Writter
		var asnCountMap = make(types.TPMSI64)			// asnMap
		var disCountMap = make(types.TPMSI64)			// 域名国内外分布

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

		// 创建ASN写出变量
		disFN := ctyFolder + constants.DISFNString + "." + constants.DISFileExtion
		fw2, err2 := os.OpenFile(disFN, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw2.Close()
		if err2 != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err2.Error()))
			os.Exit(1)
		}
		disWritter = bufio.NewWriter(fw2) // 创建新的 Writer 对象

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

			// 域名对应ASN
			if _, ok := uniqDomainMap[dnsRecordDomain]; !ok {
				uniqDomainMap[dnsRecordDomain] = ""
				dnsRecordIPv6 := strings.Split(strings.TrimRight(dnsRecordList[constants.GeoIPv6Index], ";"), ";")[0]

				// 获得ASN
				_, asnString := util.GetIPASNByMM(dnsRecordIPv6, variables.MaxMindASNReader)

				// 次数加一
				asnCountMap[asnString] ++
			}
			asnCountMap[constants.TotalTimesString] ++
		}
		util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))

		// 保存ASN结果
		asnList := make(types.ASNCList, 0)
		for asn, c := range asnCountMap {
			asnList = append(asnList, types.ASNC{asn, c})
		}
		// 降序排序
		sort.Sort(sort.Reverse(asnList))
		// 保存tld结果到v4-JSon
		asnJson, err := json.Marshal(asnList)
		_, err = asnWritter.WriteString(string(asnJson) + "\n")
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		asnWritter.Flush()

		// 保存分布结果
		disList := make(types.DisCList, 0)
		for dis, c := range disCountMap {
			disList = append(disList, types.DisC{dis, c})
		}
		// 降序排序
		sort.Sort(sort.Reverse(disList))
		// 保存tld结果到v4-JSon
		disJson, err := json.Marshal(disList)
		_, err = disWritter.WriteString(string(disJson) + "\n")
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		disWritter.Flush()
	}

	util.LogRecord("Ending: " + recordFolder + "&" + countrys + " -> " + recordFolder + "temp-" + dateSpec + "/" + countrys + "/" + constants.ASNCountFN + " & " + constants.DISFNString)
}
