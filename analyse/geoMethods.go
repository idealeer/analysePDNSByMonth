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
	"analysePDNSByMonth/types"
	"analysePDNSByMonth/util"
	"analysePDNSByMonth/variables"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
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

		// ip对应国家字典
		var ip4GeoMap = make(types.TPMSS, constants.MapAllocLen)
		var ip6GeoMap = make(types.TPMSS, constants.MapAllocLen)

		// 初始化ipv4地理字典
		if variables.V4GeoFileName != "" {
			ipFile, eO := os.Open(variables.V4GeoFileName)
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
		}

		readedCount = 0
		readedTotal = 0

		// 初始化ipv6地理字典
		if variables.V6GeoFileName != "" {
			ipFile, eO := os.Open(variables.V6GeoFileName)
			if eO != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
				os.Exit(1)
			}
			defer ipFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
			inIPFile := bufio.NewReader(ipFile)
			fileLines := util.GetLines(variables.V6GeoFileName)
			for {
				if readedCount%variables.LogShowBigLag == 0 {
					readedCount = 0
					util.LogRecord(fmt.Sprintf("Create IPv6GeoMap, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
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
				if _, ok := ip6GeoMap[ip]; !ok {
					ip6GeoMap[ip] = ipGeoList[1]
				}
			}
			util.LogRecord(fmt.Sprintf("create IPv6GeoMap, remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
			util.LogRecord(fmt.Sprintf("create IPv6GeoMap, total: %d, cost: %ds", fileLines, time.Now().Sub(timeNow)/time.Second))

		}

		// 遍历查询地理
		readedTotal = 0
		readedCount = 0
		fileLines := util.GetLines(dnsRCDFileName)

		// ip对应国家字典-new
		var ip4GeoMapNew = make(types.TPMSS, constants.MapAllocLen)
		var ip6GeoMapNew = make(types.TPMSS, constants.MapAllocLen)

		var dnsRecordNew bytes.Buffer

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
			dnsRecordIPv4s := dnsRecordList[constants.DV4IPv4Index]
			dnsRecordIPv4s = strings.TrimRight(dnsRecordIPv4s, ";")

			ipv4 := strings.Split(dnsRecordIPv4s, ";")[0]
			ipv6 := strings.Split(dnsRecordIPv6s, ";")[0]
			dnsRecordIPv6Geo := "null"
			dnsRecordIPv4Geo := "null"

			if _, ok := ip4GeoMap[ipv4]; !ok {
				if _, ok := ip4GeoMapNew[ipv4]; !ok {
					dnsRecordIPv4Geo = util.GetSingleIPGeoByMM(ipv4, variables.MaxMindReader)
					ip4GeoMapNew[ipv4] = dnsRecordIPv4Geo
				} else {
					dnsRecordIPv4Geo = ip4GeoMapNew[ipv4]
				}
			} else {
				dnsRecordIPv4Geo = ip4GeoMap[ipv4]
			}

			if _, ok := ip6GeoMap[ipv6]; !ok {
				if _, ok := ip6GeoMapNew[ipv6]; !ok {
					dnsRecordIPv6Geo = util.GetSingleIPGeoByMM(ipv6, variables.MaxMindReader)
					ip6GeoMapNew[ipv6] = dnsRecordIPv6Geo
				} else {
					dnsRecordIPv6Geo = ip6GeoMapNew[ipv6]
				}
			} else {
				dnsRecordIPv6Geo = ip6GeoMap[ipv6]
			}

			//dnsRecordNew := dnsRecord + "\t" + dnsRecordIPv6Geo + "\t" + dnsRecordIPv4Geo

			dnsRecordNew.WriteString(dnsRecord)
			dnsRecordNew.WriteByte('\t')
			dnsRecordNew.WriteString(dnsRecordIPv6Geo)
			dnsRecordNew.WriteByte('\t')
			dnsRecordNew.WriteString(dnsRecordIPv4Geo)
			dnsRecordNew.WriteByte('\n')

			// 保存添加v6+v4地理信息的记录
			_, eW := outDNSGeoFile.WriteString(dnsRecordNew.String())
			dnsRecordNew.Reset()

			if eW != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
				os.Exit(1)
			}
			outDNSGeoFile.Flush()

		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

		// 保存ipv4地理库
		readedCount = 0
		if variables.V4GeoFileName != "" {
			fw, err := os.OpenFile(variables.V4GeoFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755) // 打开或创建文件
			defer fw.Close()
			if err != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
				os.Exit(1)
			}
			outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象
			for ip, _ := range ip4GeoMapNew {
				readedCount ++

				dnsRecordNew.WriteString(ip)
				dnsRecordNew.WriteByte('\t')
				dnsRecordNew.WriteString(ip4GeoMapNew[ip])
				dnsRecordNew.WriteByte('\n')

				_, err = outWFile.WriteString(dnsRecordNew.String())
				dnsRecordNew.Reset()

				if err != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
					continue
				}
				outWFile.Flush()
			}
			util.LogRecord(fmt.Sprintf("reserve v4Geo, add %d items, cost: %ds", readedCount, time.Now().Sub(timeNow)/time.Second))
		}

		// 保存ipv6地理库
		readedCount = 0
		if variables.V6GeoFileName != "" {
			fw6, err6 := os.OpenFile(variables.V6GeoFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755) // 打开或创建文件
			defer fw6.Close()
			if err6 != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
				os.Exit(1)
			}
			outWFile6 := bufio.NewWriter(fw6) // 创建新的 Writer 对象
			for ip, _ := range ip6GeoMapNew {
				readedCount ++

				dnsRecordNew.WriteString(ip)
				dnsRecordNew.WriteByte('\t')
				dnsRecordNew.WriteString(ip6GeoMapNew[ip])
				dnsRecordNew.WriteByte('\n')

				_, err6 = outWFile6.WriteString(dnsRecordNew.String())
				dnsRecordNew.Reset()

				if err6 != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
					continue
				}
				outWFile6.Flush()
			}
			util.LogRecord(fmt.Sprintf("reserve v6Geo, add %d items, cost: %ds", readedCount, time.Now().Sub(timeNow)/time.Second))
		}

		// 优化
		ip4GeoMap = nil
		ip6GeoMap = nil
		ip4GeoMapNew = nil
		ip6GeoMapNew = nil
		util.LogRecord(fmt.Sprintf("debug.FreeOSMemory()"))
		debug.FreeOSMemory()

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
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-ip-file parm]", eOOO.Error()))
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

	var dnsRecordNew bytes.Buffer

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
		ipGeo := "null"
		if ip != "null" {
			ipGeo = util.GetSingleIPGeoByMM(ip, variables.MaxMindReader)
		}
		//dnsRecordNew := ip + "\t" + ipGeo

		dnsRecordNew.WriteString(ip)
		dnsRecordNew.WriteByte('\t')
		dnsRecordNew.WriteString(ipGeo)
		dnsRecordNew.WriteByte('\n')

		// 保存添加IP地理信息的记录
		_, eW := outDNSGeoFile.WriteString(dnsRecordNew.String())
		dnsRecordNew.Reset()

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

/*
	获得ipCity信息
 */
func getCity(ips string) {
	ipList := strings.Split(strings.TrimRight(ips, ","), ",")
	for _, ip := range ipList {
		geoNum, cityStr := util.GetIPCityByMM(ip, variables.MaxMindCityReader)
		util.LogRecord(fmt.Sprintf("%s\t%d\t%s", ip, geoNum, cityStr))
	}
}

/*
	获得ip文件City信息
 */
func getCityByFile(ipFileName string, ipCityFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + ipFileName + " & " + variables.MaxMindCityDBName + " -> " + ipCityFileName)

	// 打开文件
	dnsFile, eOOO := os.Open(ipFileName)
	if eOOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-ip-file parm]", eOOO.Error()))
		os.Exit(1)
	}
	defer dnsFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

	// 创建文件
	fw, eOO := os.OpenFile(ipCityFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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
		geoNum, cityStr := util.GetIPCityByMM(ip, variables.MaxMindCityReader)

		dnsRecordNew := fmt.Sprintf("%s\t%d\t%s\n", ip, geoNum, cityStr)

		// 保存添加IPASN信息的记录
		_, eW := outDNSGeoFile.WriteString(dnsRecordNew)

		if eW != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
			os.Exit(1)
		}
		outDNSGeoFile.Flush()

	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

	util.LogRecord("Ending: " + ipFileName + " & " + variables.MaxMindCityDBName + " -> " + ipCityFileName)
}

/*
	获得ip经纬度信息
 */
func getLonLa(ips string) {
	ipList := strings.Split(strings.TrimRight(ips, ","), ",")
	for _, ip := range ipList {
		cty, lon, la := util.GetIPLonLaByMM(ip, variables.MaxMindCityReader)
		util.LogRecord(fmt.Sprintf("%s\t%s\t%s\t%s", ip, cty, strconv.FormatFloat(lon , 'f', 11, 64), strconv.FormatFloat(la, 'f', 11, 64)))
	}
}

/*
	获得ip文件经纬度信息
 */
func getLonLaByFile(ipFileName string, ipLonLaFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + ipFileName + " & " + variables.MaxMindCityDBName + " -> " + ipLonLaFileName)

	// 打开文件
	dnsFile, eOOO := os.Open(ipFileName)
	if eOOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-ip-file parm]", eOOO.Error()))
		os.Exit(1)
	}
	defer dnsFile.Close() // 该函数执行完毕退出前才会执行defer后的语句

	// 创建文件
	fw, eOO := os.OpenFile(ipLonLaFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
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
		cty, lon, la := util.GetIPLonLaByMM(ip, variables.MaxMindCityReader)

		dnsRecordNew := fmt.Sprintf("%s\t%s\t%s\t%s\n", ip, cty, strconv.FormatFloat(lon , 'f', 11, 64), strconv.FormatFloat(la, 'f', 11, 64))

		// 保存添加IP经纬度信息的记录
		_, eW := outDNSGeoFile.WriteString(dnsRecordNew)

		if eW != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
			os.Exit(1)
		}
		outDNSGeoFile.Flush()

	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

	util.LogRecord("Ending: " + ipFileName + " & " + variables.MaxMindCityDBName + " -> " + ipLonLaFileName)
}


/*
	获得IPv6地址的经纬度分布
 */
func GetIPv6LonLa() {
	variables.IPLonLaName = GetResFileName(time.Now().Format(fmt.Sprintf("%s-%s", constants.IPLLName, constants.DateFormat)), constants.IPLLExtion)
	variables.IPCNLonLaName = GetResFileName(time.Now().Format(fmt.Sprintf("%s-%s", constants.IPCNLLName, constants.DateFormat)), constants.IPCNLLExtion)
	ggetIPv6LonLa(variables.V6GeoFileName, variables.IPLonLaName, variables.IPCNLonLaName)
}

/*
	获得IPv6地址的经纬度分布
 */
func ggetIPv6LonLaList(ipFileName string, llAllFileName string, llCNFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + ipFileName + " & " + variables.MaxMindCityDBName + " -> " + llAllFileName + " & " + llCNFileName)

	// 打开文件
	ipFile, eOOO := os.Open(ipFileName)
	if eOOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\n", eOOO.Error()))
		os.Exit(1)
	}
	defer ipFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inIPFile := bufio.NewReader(ipFile)


	// 创建全体经纬度文件
	fwAll, eOO := os.OpenFile(llAllFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fwAll.Close()
	if eOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
		os.Exit(1)
	}
	outAllFile := bufio.NewWriter(fwAll) // 创建新的 Writer 对象

	// 创建国内经纬度文件
	fwCN, eOO := os.OpenFile(llCNFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fwCN.Close()
	if eOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
		os.Exit(1)
	}
	outCNFile := bufio.NewWriter(fwCN) // 创建新的 Writer 对象

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	fileLines := util.GetLines(ipFileName)

	// 经纬度结果
	var llAllList = make(types.LonLaList, 0)
	var llCNList = make(types.LonLaList, 0)


	// 遍历IPv6
	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		ipCtyBytes, _, e := inIPFile.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		ipCty := string(ipCtyBytes)
		ipCty = strings.TrimRight(ipCty, "\n")
		ipCtyList := strings.Split(ipCty, "\t")
		ip := ipCtyList[0]
		cty := ipCtyList[1]

		_, lon, la := util.GetIPLonLaByMM(ip, variables.MaxMindCityReader)

		// 无效
		if lon == constants.LonNullNum {
			continue
		}

		// 所有经纬度
		llAllList = append(llAllList, types.LonLa{lon, la})

		// 中国经纬度
		if cty == constants.GeoCNString {
			llCNList = append(llCNList, types.LonLa{lon, la})
		}

	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

	// 保存添加IPASN信息的记录
	util.LogRecord(fmt.Sprintf("Reserve reslut"))

	// 保存所有经纬度结果到JSon
	jsonBytes6, err6 := json.Marshal(llAllList)
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	_, eW := outAllFile.WriteString(string(jsonBytes6))
	if eW != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
		os.Exit(1)
	}
	outAllFile.Flush()

	// 保存国内经纬度结果到JSon
	jsonBytes6, err6 = json.Marshal(llCNList)
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	_, eW = outCNFile.WriteString(string(jsonBytes6))
	if eW != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
		os.Exit(1)
	}
	outCNFile.Flush()

	util.LogRecord("Ending: " + ipFileName + " & " + variables.MaxMindCityDBName + " -> " + llAllFileName + " & " + llCNFileName)
}

/*
	获得IPv6地址的经纬度分布
 */
func ggetIPv6LonLa(ipFileName string, llAllFileName string, llCNFileName string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " + ipFileName + " & " + variables.MaxMindCityDBName + " -> " + llAllFileName + " & " + llCNFileName)

	// 打开文件
	ipFile, eOOO := os.Open(ipFileName)
	if eOOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\n", eOOO.Error()))
		os.Exit(1)
	}
	defer ipFile.Close() // 该函数执行完毕退出前才会执行defer后的语句
	inIPFile := bufio.NewReader(ipFile)


	// 创建全体经纬度文件
	fwAll, eOO := os.OpenFile(llAllFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fwAll.Close()
	if eOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
		os.Exit(1)
	}
	outAllFile := bufio.NewWriter(fwAll) // 创建新的 Writer 对象

	// 创建国内经纬度文件
	fwCN, eOO := os.OpenFile(llCNFileName, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fwCN.Close()
	if eOO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eOO.Error()))
		os.Exit(1)
	}
	outCNFile := bufio.NewWriter(fwCN) // 创建新的 Writer 对象

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	fileLines := util.GetLines(ipFileName)

	// 经纬度结果
	var llAllList = make(types.LonLaSimList, 0)
	var llCNList = make(types.LonLaSimList, 0)


	// 遍历IPv6
	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		ipCtyBytes, _, e := inIPFile.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		ipCty := string(ipCtyBytes)
		ipCty = strings.TrimRight(ipCty, "\n")
		ipCtyList := strings.Split(ipCty, "\t")
		ip := ipCtyList[0]
		cty := ipCtyList[1]

		_, lon, la := util.GetIPLonLaByMM(ip, variables.MaxMindCityReader)

		// 无效
		if lon == constants.LonNullNum {
			continue
		}

		// 所有经纬度
		llAllList = append(llAllList, types.LonLaSim{lon, la})

		// 中国经纬度
		if cty == constants.GeoCNString {
			llCNList = append(llCNList, types.LonLaSim{lon, la})
		}

	}
	util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))

	// 保存添加IPASN信息的记录
	util.LogRecord(fmt.Sprintf("Reserve reslut"))

	// 保存所有经纬度结果到JSon
	jsonBytes6, err6 := json.Marshal(llAllList)
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	_, eW := outAllFile.WriteString(string(jsonBytes6))
	if eW != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
		os.Exit(1)
	}
	outAllFile.Flush()

	// 保存国内经纬度结果到JSon
	jsonBytes6, err6 = json.Marshal(llCNList)
	if err6 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err6.Error()))
		os.Exit(1)
	}
	_, eW = outCNFile.WriteString(string(jsonBytes6))
	if eW != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eW.Error()))
		os.Exit(1)
	}
	outCNFile.Flush()

	util.LogRecord("Ending: " + ipFileName + " & " + variables.MaxMindCityDBName + " -> " + llAllFileName + " & " + llCNFileName)
}

