/*
@File : geoMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 09:00
*/

package analyse

import (
	"analysePDNSByMonth/constants"
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
	获得dns记录的V6+V4地理信息
 */
func getV6V4Geo(dnsRCDFileName string, dnsRCDV6GeoV4GeoFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + dnsRCDFileName + " & " + variables.MaxMindDBName + " -> " + dnsRCDV6GeoV4GeoFileName)

	if util.FileIsNotExist(dnsRCDV6GeoV4GeoFileName) {
		// 创建dns地理文件
		fw, eOO := os.OpenFile(dnsRCDV6GeoV4GeoFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if eOO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
			os.Exit(1)
		}
		outDNSGeoFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 打开dns记录文件
		dnsFile, eOOO := os.Open(dnsRCDFileName)
		if eOOO != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eOOO.Error()))
			os.Exit(1)
		}
		defer dnsFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

		inDNSFile := bufio.NewReader(dnsFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0
		fileLines := util.GetLines(dnsRCDFileName)

		for {
			if readedCount%variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			dnsRecordBytes, _, e := inDNSFile.ReadLine()
			if e == io.EOF {
				break
			}
			readedCount++
			readedTotal++
			dnsRecord := string(dnsRecordBytes)
			dnsRecordList := strings.Split(dnsRecord, "\t")
			dnsRecordIPv6s := dnsRecordList[constants.DV4IPv6Index]
			dnsRecordIPv6s = strings.TrimRight(dnsRecordIPv6s, ";")
			dnsRecordIPv6Geo := util.GetIPGeoByMM(dnsRecordIPv6s, variables.MaxMindReader, constants.NoIPv4Geo, constants.IPv6Geo)
			dnsRecordIPv4s := dnsRecordList[constants.DV4IPv4Index]
			dnsRecordIPv4s = strings.TrimRight(dnsRecordIPv4s, ";")
			dnsRecordIPv4Geo := util.GetIPGeoByMM(dnsRecordIPv4s, variables.MaxMindReader, constants.IPv4Geo, constants.NoIPv6Geo)

			dnsRecordNew := dnsRecord + "\t" + dnsRecordIPv6Geo + "\t" + dnsRecordIPv4Geo

			// 保存添加v6+v4地理信息的记录
			_, eW := outDNSGeoFile.WriteString(dnsRecordNew + "\n")
			if eW != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
				os.Exit(1)
			}
			outDNSGeoFile.Flush()

		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else{
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", dnsRCDV6GeoV4GeoFileName, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord("Ending: " + dnsRCDFileName + " & " + variables.MaxMindDBName + " -> " + dnsRCDV6GeoV4GeoFileName)
}

/*
	获得ip文件的地理信息
 */
func getGeoByFile(ipFileName string, ipGeoFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + ipFileName + " & " + variables.MaxMindDBName + " -> " + ipGeoFileName)

	// 打开文件
	dnsFile, eOOO := os.Open(ipFileName)
	if eOOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-id parm]", eOOO.Error()))
		os.Exit(1)
	}
	defer dnsFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

	// 创建文件
	fw, eOO := os.OpenFile(ipGeoFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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
		ip = strings.TrimRight(ip, ";")
		ipGeo := "null;null;null;null"
		if ip != "null" {
			ipGeo = util.GetIPGeoByMM(ip, variables.MaxMindReader, constants.IPv4Geo, constants.IPv6Geo)
		}
		dnsRecordNew := ip + "\t" + ipGeo

		// 保存添加IP地理信息的记录
		_, eW := outDNSGeoFile.WriteString(dnsRecordNew + "\n")
		if eW != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
			os.Exit(1)
		}
		outDNSGeoFile.Flush()

	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

	util.LogRecord("Ending: " + ipFileName + " & " + variables.MaxMindDBName + " -> " + ipGeoFileName)
}

/*
	获得ip地理信息
 */
func getGeo(ips string) {
	ipList := strings.Split(strings.TrimRight(ips, ","), ",")
	for _, ip := range ipList {
		util.LogRecord(ip + "\t" + util.GetIPGeoByMM(ip, variables.MaxMindReader, constants.IPv4Geo, constants.IPv6Geo))
	}
}

/*
	获得地理差异
 */
func getGeoPercentByFile(dnsRCDFileName string) {
	timeNow := time.Now()
	// 打开dns记录文件
	dnsFile, eOOO := os.Open(dnsRCDFileName)
	if eOOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eOOO.Error()))
		os.Exit(1)
	}
	defer dnsFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

	inDNSFile := bufio.NewReader(dnsFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	fileLines := util.GetLines(dnsRCDFileName)
	var percentFirst float64 = 0
	var percentCount float64 = 0

	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		dnsRecordBytes, _, e := inDNSFile.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		dnsRecord := string(dnsRecordBytes)
		dnsRecordList := strings.Split(dnsRecord, "\t")
		dnsRecordIPv6s := dnsRecordList[2]
		dnsRecordIPv6s = strings.TrimRight(dnsRecordIPv6s, ";")
		percentCount ++
		percentFirst += util.GetIPGeosPercentByMM(dnsRecordIPv6s, variables.MaxMindReader, constants.NoIPv4Geo, constants.IPv6Geo)

	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

	util.LogRecord(fmt.Sprintf("第一个地理在每条记录中的比例: "))
	fmt.Println(percentFirst / percentCount)
}
