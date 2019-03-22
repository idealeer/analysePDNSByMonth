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
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

/*
	去除重复域名，同时查询域名v4地址库，存在的不需要再次查询
 */
func uniqueDomainNoOpt(fileName string, fileNameNew string, d4FileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " & " + variables.D4FileName + " -> " + fileNameNew + " & " + d4FileName)

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

		var domainMap = make(types.TPMSS)

		// 去除重复域名
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

		// 重复域名输出
		fw, err := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 保存去重域名，如果提供域名v4地址字典，则不必写入域名v4地址文件，不用再次nslook查询
		if variables.D4FileName == "" {
			readedTotal = 0
			for domain, _ := range domainMap {
				if readedTotal%variables.LogShowBigLag == 0 {
					util.LogRecord(fmt.Sprintf("writing uniqDomain total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
				}
				readedTotal++
				_, err = outWFile.WriteString(domain + "\n")
				if err != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
					continue
				}
				outWFile.Flush()
			}
			util.LogRecord(fmt.Sprintf("writing uniqDomain total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
		} else {
			// 提供了域名v4地址字典文件
			// 域名对应IP字典
			var domainIPMap = make(types.TPMSS)

			var readedCount uint64 = 0
			var readedTotal uint64 = 0
			var fileLines = util.GetLines(variables.D4FileName)
			var domain string

			// 读入ip文件，构建字典
			ipFile, eO := os.Open(variables.D4FileName)
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

			// 创建域名v4文件
			d4File, eOO := os.OpenFile(d4FileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
			defer d4File.Close()
			if eOO != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
				os.Exit(1)
			}
			outD4File := bufio.NewWriter(d4File)

			// 遍历域名
			readedTotal = 0
			for domain, _ := range domainMap {
				if readedTotal%variables.LogShowBigLag == 0 {
					util.LogRecord(fmt.Sprintf("writing uniqDomain | uniqDomainIpv4 total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
				}
				readedTotal++

				if _, ok := domainIPMap[domain]; !ok {	// 需要ns查询，列入uniq文件
					_, err = outWFile.WriteString(domain + "\n")
					if err != nil {
						util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
						continue
					}
					outWFile.Flush()
				} else {	// 不需要ns查询
					_, err = outD4File.WriteString(domain + "\t" + domainIPMap[domain] + "\n")
					if err != nil {
						util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
						continue
					}
					outD4File.Flush()
				}
			}
			util.LogRecord(fmt.Sprintf("writing uniqDomain | uniqDomainIpv4 total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " +  fileName + " & " + variables.D4FileName + " -> " + fileNameNew + " & " + d4FileName)
}

/*
	去除重复域名，同时查询域名v4地址库，存在的不需要再次查询，去重时判断是否查询，内存4.5-5G
 */
func uniqueDomain1(fileName string, fileNameNew string, d4FileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " & " + variables.D4FileName + " -> " + fileNameNew + " & " + d4FileName)

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
		var fileLines uint64

		var domainIPMap = make(types.TPMSS)

		var outD4File *bufio.Writer		// 直接输出到uniqDomainV4文件，不需要ns查询

		// 提供了域名v4地址字典文件, 创建域名对应IP字典
		if variables.D4FileName != "" {
			fileLines := util.GetLines(variables.D4FileName)
			domainIPMap = make(types.TPMSS, fileLines)
			var domain string

			// 读入ip文件，构建字典
			ipFile, eO := os.Open(variables.D4FileName)
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
				//if _, ok := domainIPMap[domain]; !ok {
				// 已经去重过了
				domainIPMap[domain] = domainIPList[constants.UIPv4Index]
				//}
			}
			util.LogRecord(fmt.Sprintf("Create DomainIPMap, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

			// 创建域名v4文件
			d4File, eOO := os.OpenFile(d4FileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
			defer d4File.Close()
			if eOO != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
				os.Exit(1)
			}
			outD4File = bufio.NewWriter(d4File)
		}

		// 去除重复域名
		readedCount = 0
		readedTotal = 0
		fileLines = util.GetLines(fileName)
		var domainMap = make(types.TPMSS, constants.MapAllocLen / 10 * 4)			// 需要查询的
		var domainPutMap = make(types.TPMSB, constants.MapAllocLen / 10 * 8)		// 是否已经输出到uniqDomainIPv4
		var existedD4Count uint64 = 0

		var resStr bytes.Buffer

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

			// 判断是否需要ns
			if _, ok := domainIPMap[dnsRecordDomain]; !ok { // 需要ns查询，列入uniq文件
				if _, ok := domainMap[dnsRecordDomain]; !ok {
					domainMap[dnsRecordDomain] = ""
				}
			} else { // 不需要ns查询，直接输出到等d4文件，判断是否已经输出
				if _, ok := domainPutMap[dnsRecordDomain]; !ok {

					resStr.WriteString(dnsRecordDomain)
					resStr.WriteByte('\t')
					resStr.WriteString(domainIPMap[dnsRecordDomain])
					resStr.WriteByte('\n')

					_, err1 := outD4File.WriteString(resStr.String())
					resStr.Reset()
					if err1 != nil {
						util.LogRecord(fmt.Sprintf("Error: %s", err1.Error()))
						continue
					}
					outD4File.Flush()
					domainPutMap[dnsRecordDomain] = true
					existedD4Count ++
				}
			}
		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		util.LogRecord(fmt.Sprintf("total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
		util.LogRecord(fmt.Sprintf("existed domainIPv4: %d, cost: %ds", existedD4Count, time.Now().Sub(timeNow)/time.Second))

		// 优化
		domainIPMap = nil
		domainPutMap = nil
		util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
		debug.FreeOSMemory()

		// 去重域名输出
		fw, err2 := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if err2 != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err2.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		readedTotal = 0
		for domain, _ := range domainMap {
			if readedTotal%variables.LogShowBigLag == 0 {
				util.LogRecord(fmt.Sprintf("writing uniqDomain total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
			}
			readedTotal++

			resStr.WriteString(domain)
			resStr.WriteByte('\n')

			_, err = outWFile.WriteString(resStr.String())
			resStr.Reset()
			if err != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
				continue
			}
			outWFile.Flush()
		}

		// 优化
		domainMap = nil
		util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
		debug.FreeOSMemory()

		util.LogRecord(fmt.Sprintf("writing uniqDomain total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))

	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow)/time.Second))
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " +  fileName + " & " + variables.D4FileName + " -> " + fileNameNew + " & " + d4FileName)
}

/*
	去除重复域名，同时查询域名v4地址库，存在的不需要再次查询，先去重后判断是否查询，速度快、内存小3-3.5G
 */
func uniqueDomain(fileName string, fileNameNew string, d4FileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  fileName + " & " + variables.D4FileName + " -> " + fileNameNew + " & " + d4FileName)

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

		var domainMap = make(types.TPMSS, constants.MapAllocLen)

		var resStr bytes.Buffer

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

		// 保存去重域名，如果提供域名v4地址字典，则直接写入域名v4地址文件，不用再次nslook查询
		if variables.D4FileName == "" {
			readedTotal = 0
			for domain, _ := range domainMap {
				if readedTotal%variables.LogShowBigLag == 0 {
					util.LogRecord(fmt.Sprintf("writing uniqDomain total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
				}
				readedTotal++

				resStr.WriteString(domain)
				resStr.WriteByte('\n')

				_, err = outWFile.WriteString(resStr.String())
				resStr.Reset()
				if err != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
					continue
				}
				outWFile.Flush()
			}
			util.LogRecord(fmt.Sprintf("writing uniqDomain total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
		} else {
			// 提供了域名v4地址字典文件
			// 域名对应IP字典

			var readedCount uint64 = 0
			var readedTotal uint64 = 0
			var fileLines = util.GetLines(variables.D4FileName)
			var domainIPMap = make(types.TPMSS, fileLines)

			var domain string

			// 读入ip文件，构建字典
			ipFile, eO := os.Open(variables.D4FileName)
			if eO != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
				os.Exit(1)
			}
			defer ipFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
			inIPFile := bufio.NewReader(ipFile)
			for {
				if readedCount%variables.LogShowBigLag == 0 {
					readedCount = 0
					util.LogRecord(fmt.Sprintf("create DomainIPMap, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
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
				//if _, ok := domainIPMap[domain]; !ok {
				// 已经去重过了，不必再次检测
				domainIPMap[domain] = domainIPList[constants.UIPv4Index]
				//}
			}
			util.LogRecord(fmt.Sprintf("create DomainIPMap, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

			// 创建域名v4文件
			d4File, eOO := os.OpenFile(d4FileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
			defer d4File.Close()
			if eOO != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
				os.Exit(1)
			}
			outD4File := bufio.NewWriter(d4File)

			// 遍历域名
			readedTotal = 0
			readedCount = 0
			for domain, _ := range domainMap {
				if readedTotal%variables.LogShowBigLag == 0 {
					util.LogRecord(fmt.Sprintf("writing uniqDomain | uniqDomainIpv4 total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
				}
				readedTotal ++

				if _, ok := domainIPMap[domain]; !ok {	// 需要ns查询，列入uniq文件

					resStr.WriteString(domain)
					resStr.WriteByte('\n')

					_, err = outWFile.WriteString(resStr.String())
					resStr.Reset()
					if err != nil {
						util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
						continue
					}
					outWFile.Flush()
					readedCount ++
				} else {	// 不需要ns查询

					resStr.WriteString(domain)
					resStr.WriteByte('\t')
					resStr.WriteString(domainIPMap[domain])
					resStr.WriteByte('\n')

					_, err = outD4File.WriteString(resStr.String())
					resStr.Reset()
					if err != nil {
						util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
						continue
					}
					outD4File.Flush()
				}
			}

			// 优化
			domainIPMap = nil
			util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
			debug.FreeOSMemory()

			util.LogRecord(fmt.Sprintf("writing uniqDomain | uniqDomainIpv4 total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
			util.LogRecord(fmt.Sprintf("writing uniqDomain total: %d, cost: %ds", readedCount, time.Now().Sub(timeNow)/time.Second))

		}

		// 优化
		domainMap = nil
		util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
		debug.FreeOSMemory()

	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " +  fileName + " & " + variables.D4FileName + " -> " + fileNameNew + " & " + d4FileName)
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

		var resStr bytes.Buffer

		var domainMap = make(types.TPMSS, constants.MapAllocLen) // 去重后域名map：[域名]("v6-cty\tv4-cty")

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

				resStr.WriteString(dnsRecordV6Cty)
				resStr.WriteByte('\t')
				resStr.WriteString(dnsRecordV4Cty)

				domainMap[dnsRecordDomain] = resStr.String()
				resStr.Reset()
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
			readedCount++
			readedTotal++

			resStr.WriteString(domain)
			resStr.WriteByte('\t')
			resStr.WriteString(cty)
			resStr.WriteByte('\n')

			_, eW := outWFile.WriteString(resStr.String())
			resStr.Reset()
			if eW != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
				continue
			}
			outWFile.Flush()
		}

		// 优化
		domainMap = nil
		util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
		debug.FreeOSMemory()

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

		var resStr bytes.Buffer

		var ipv6Map = make(types.TPMSS, constants.MapAllocLen) // 去重后ipv6-map：[ipv6]("v6-cty\tv4cty")

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

					resStr.WriteString(dnsRecordV6Cty)
					resStr.WriteByte('\t')
					resStr.WriteString(dnsRecordV4Cty)

					ipv6Map[ipv6] = resStr.String()
					resStr.Reset()
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
			readedCount++
			readedTotal++

			resStr.WriteString(ipv6)
			resStr.WriteByte('\t')
			resStr.WriteString(cty)
			resStr.WriteByte('\n')

			_, eW := outWFile.WriteString(resStr.String())
			resStr.Reset()

			if eW != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
				continue
			}
			outWFile.Flush()
		}

		// 优化
		ipv6Map = nil
		util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
		debug.FreeOSMemory()

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

		var resStr bytes.Buffer

		var sldMap = make(types.TPMSTPMSI64, constants.MapAllocLen) // 去重后SLD-map：[country]([sld](count))

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

			resStr.WriteString(dnsRecordSubDomainList[dnsRecordSubDomainListLen-2])
			resStr.WriteByte('.')
			resStr.WriteString(dnsRecordSubDomainList[dnsRecordSubDomainListLen-1])

			dnsRecordSLD := resStr.String()
			resStr.Reset()

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
				readedCount++
				readedTotal++

				resStr.WriteString(sld)
				resStr.WriteByte('\t')
				resStr.WriteString(strconv.FormatInt(count, 10))
				resStr.WriteByte('\t')
				resStr.WriteString(country)
				resStr.WriteByte('\n')

				_, eW := outWFile.WriteString(resStr.String())
				resStr.Reset()

				if eW != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
					continue
				}
				outWFile.Flush()
			}
		}

		// 优化
		sldMap = nil
		util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
		debug.FreeOSMemory()

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

		var resStr bytes.Buffer

		var sldMap = make(types.TPMSTPMSI64, constants.MapAllocLen) // 去重后SLD-map：[country]([sld](count))

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

			resStr.WriteString(dnsRecordSubDomainList[dnsRecordSubDomainListLen-2])
			resStr.WriteByte('.')
			resStr.WriteString(dnsRecordSubDomainList[dnsRecordSubDomainListLen-1])

			dnsRecordSLD := resStr.String()
			resStr.Reset()

			dnsRecordCount, _ := strconv.ParseInt(dnsRecordList[constants.GeoCountIndex], 10, 64)   // 次数
			dnsRecordV4Cty := dnsRecordList[constants.GeoV4GIndex]

			// 国家是否存在
			if sldMap[dnsRecordV4Cty] == nil {
				sMap := make(types.TPMSI64)
				sldMap[dnsRecordV4Cty] = sMap
			}
			sldMap[dnsRecordV4Cty][dnsRecordSLD] += dnsRecordCount

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
				readedCount++
				readedTotal++

				resStr.WriteString(sld)
				resStr.WriteByte('\t')
				resStr.WriteString(strconv.FormatInt(count, 10))
				resStr.WriteByte('\t')
				resStr.WriteString(country)
				resStr.WriteByte('\n')

				_, eW := outWFile.WriteString(resStr.String())
				resStr.Reset()

				if eW != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
					continue
				}
				outWFile.Flush()
			}
		}

		// 优化
		sldMap = nil
		util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
		debug.FreeOSMemory()

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

		var tldMap = make(types.TPMSI64, 1000)

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

		// 优化
		tldMap = nil
		util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
		debug.FreeOSMemory()

		util.LogRecord(fmt.Sprintf("writing total: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: " + fileName + " -> " + fileNameNew)
}
