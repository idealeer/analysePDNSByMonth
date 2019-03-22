/*
@File : extractMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 08:35
*/

package analyse

import (
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/types"
	"analysePDNSByMonth/util"
	"analysePDNSByMonth/variables"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

/*
	提取简单IPv4地址
 */
func getSimpleIPv4(fileName string, fileNameNew string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + "->" + fileNameNew)

	fw, err := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755) // 打开或创建文件
	defer fw.Close()
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

	// 同时保存到d4文件，便于下次使用
	var outWFile4 *bufio.Writer
	if variables.D4FileName != "" {
		fw4, err4 := os.OpenFile(variables.D4FileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755) // 打开或创建文件
		defer fw4.Close()
		if err4 != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err4.Error()))
			os.Exit(1)
		}
		outWFile4 = bufio.NewWriter(fw4) // 创建新的 Writer 对象
	}

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

	var resStr bytes.Buffer

	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		zdnsJsonBytes, _, e := br.ReadLine()
		if e == io.EOF {
			break
		}

		readedCount++
		readedTotal++

		zdnsDomainIPv4 := util.ZDNSALookUpJson2String(zdnsJsonBytes)

		resStr.WriteString(zdnsDomainIPv4)
		resStr.WriteByte('\n')

		_, err = outWFile.WriteString(resStr.String())
		resStr.Reset()

		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			continue
		}
		outWFile.Flush()

		if variables.D4FileName != "" {
			resStr.WriteString(zdnsDomainIPv4)
			resStr.WriteByte('\n')
			_, err = outWFile4.WriteString(resStr.String())
			resStr.Reset()

			if err != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
				continue
			}
			outWFile4.Flush()
		}
	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

	util.LogRecord("Ending: " + fileName + "->"  + fileNameNew)
}

/*
	获得指定国家的记录及去重IPv6地址
 */
func getSpecCountryRecordAndUniqIPv6() {
	ggetSpecCountryRecordAndUniqIPv6(variables.ScanCountrys, variables.RecordHisDir, variables.ScanDateSpec, variables.ScanDateBefore)
}

/*
	获得指定国家的记录及去重IPv6\IPv4地址
 */
func ggetSpecCountryRecordAndUniqIPv6(countrys string, recordFolder string, dateSpec string, dateBefore string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + recordFolder + "&" + countrys + " -> " + recordFolder + "temp-" + dateSpec + "/" + countrys)

	var ctyUniqIPv6Map = make(types.TPMSTPMSS)					// 每个国家的去重IPv6字典
	var ctyRecordWritter = make(map[string]*bufio.Writer)		// 每个国家的recordWritter
	var ctyUniqIPv6Writter = make(map[string]*bufio.Writer)		// 每个国家的uniqRecordWritter
	var ctyUniqIPv4Map = make(types.TPMSTPMSS)					// 每个国家的去重IPv4字典
	var ctyUniqIPv4Writter = make(map[string]*bufio.Writer)		// 每个国家的uniqRecordWritter

	var ctyMap = make (types.TPMSS)

	// 创建文件夹准备
	for _, cty := range strings.Split(countrys, ",") {
		if _, ok := ctyUniqIPv6Map[cty]; !ok {
			u6Map := make(types.TPMSS, constants.YWTimes)
			ctyUniqIPv6Map[cty] = u6Map
			u4Map := make(types.TPMSS, constants.YWTimes)
			ctyUniqIPv4Map[cty] = u4Map
			ctyMap[cty] = cty
		}
		// 创建国家文件夹
		ctyFolder := recordFolder + constants.DNSTempFolder + "-" + variables.DNSDateSpec + string(os.PathSeparator) + cty + string(os.PathSeparator)
		_, err := os.Stat(ctyFolder)
		if err != nil {
			ec := os.Mkdir(ctyFolder, os.ModePerm)
			if ec != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
				os.Exit(1)
			}
		}
		// 创建record写出变量
		ctyRecordFN := ctyFolder + constants.ScanRecordString + "." + constants.ScanFileExtion
		fw1, err1 := os.OpenFile(ctyRecordFN, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw1.Close()
		if err1 != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err1.Error()))
			os.Exit(1)
		}
		ctyRecordWritter[cty] = bufio.NewWriter(fw1) // 创建新的 Writer 对象
		// 创建uniqIPv6写出变量
		ctyUniqIPv6FN := ctyFolder + constants.ScanUniqIPv6String + "." + constants.ScanFileExtion
		fw2, err2 := os.OpenFile(ctyUniqIPv6FN, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw2.Close()
		if err2 != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err2.Error()))
			os.Exit(1)
		}
		ctyUniqIPv6Writter[cty] = bufio.NewWriter(fw2) // 创建新的 Writer 对象
		// 创建uniqIPv4写出变量
		ctyUniqIPv4FN := ctyFolder + constants.ScanUniqIPv4String + "." + constants.ScanFileExtion
		fw3, err3 := os.OpenFile(ctyUniqIPv4FN, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw3.Close()
		if err3 != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err3.Error()))
			os.Exit(1)
		}
		ctyUniqIPv4Writter[cty] = bufio.NewWriter(fw3) // 创建新的 Writer 对象
	}

	// 获得区间日期月份
	ymList, ymLen := util.GetSpecYMsByYMStr(dateBefore, dateSpec)

	for index, ym := range ymList {
		trFN := recordFolder + constants.DNSTempFolder + "-" + ym + string(os.PathSeparator) + constants.DNSFileV6GeoV4GeoName

		// 打开记录文件
		srcFile, err := os.Open(trFN)
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		defer srcFile.Close()	// 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0

		for {
			if readedCount % variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("temp-%s: readedtotal: %d, remind: %d files, cost: %ds", ym, readedTotal, ymLen - index - 1, time.Now().Sub(timeNow) / time.Second))
			}
			lineBytes, _, eR := br.ReadLine()
			if eR == io.EOF {
				break
			}
			readedCount++
			readedTotal++

			lineString := string(lineBytes)
			dnsRecordList := strings.Split(lineString, "\t")
			dnsRecordV4Geo := dnsRecordList[constants.GeoV4GIndex]			// v4地理

			// 属于分析的国家
			if _, ok := ctyMap[dnsRecordV4Geo]; ok {
				dnsRecordIPv6List := strings.Split(strings.TrimRight(dnsRecordList[constants.GeoIPv6Index], ";"), ";")
				dnsRecordIPv4List := strings.Split(strings.TrimRight(dnsRecordList[constants.GeoIPv4Index], ";"), ";")

				// 输出记录
				_, err = ctyRecordWritter[dnsRecordV4Geo].WriteString(lineString + "\n")
				if err != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
					os.Exit(1)
				}
				ctyRecordWritter[dnsRecordV4Geo].Flush()

				// 输出IPv6地址
				for _, dnsRecordIPv6 := range dnsRecordIPv6List {
					// 不属于有效IPv6地址
					if util.IsNotSigIPv6(dnsRecordIPv6) {
						continue
					}
					if _, ok := ctyUniqIPv6Map[dnsRecordV4Geo][dnsRecordIPv6]; !ok {

						// 输出记录
						_, err = ctyUniqIPv6Writter[dnsRecordV4Geo].WriteString(dnsRecordIPv6 + "\n")
						if err != nil {
							util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
							os.Exit(1)
						}
						ctyUniqIPv6Writter[dnsRecordV4Geo].Flush()

						ctyUniqIPv6Map[dnsRecordV4Geo][dnsRecordIPv6] = ""
					}
				}

				// 输出IPv4地址
				for _, dnsRecordIPv4 := range dnsRecordIPv4List {
					if _, ok := ctyUniqIPv4Map[dnsRecordV4Geo][dnsRecordIPv4]; !ok {

						// 输出记录
						_, err = ctyUniqIPv4Writter[dnsRecordV4Geo].WriteString(dnsRecordIPv4 + "\n")
						if err != nil {
							util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
							os.Exit(1)
						}
						ctyUniqIPv4Writter[dnsRecordV4Geo].Flush()

						ctyUniqIPv4Map[dnsRecordV4Geo][dnsRecordIPv4] = ""
					}
				}
			}
		}
		util.LogRecord(fmt.Sprintf("temp-%s: readedtotal: %d, remind: %d files, cost: %ds", ym, readedTotal, ymLen - index - 1, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord("Ending: " + recordFolder + "&" + countrys + " -> " + recordFolder + "temp-" + dateSpec + "/" + countrys)
}
