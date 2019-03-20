/*
@File : nmapMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-20 19:11
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

/*
	提取简单Nmap端口扫描结果
 */
func extractNmapPortResult(){

	for _, cty := range strings.Split(variables.ScanCountrys, ",") {
		// ipv6端口
		nmapIPv6FN := variables.RecordHisDir + constants.DNSTempFolder + "-" + variables.DNSDateSpec + string(os.PathSeparator) + cty + string(os.PathSeparator) + constants.NmapIPv6File + "." + constants.NmapFileExtion
		portIPv6FN := variables.RecordHisDir + constants.DNSTempFolder + "-" + variables.DNSDateSpec + string(os.PathSeparator) + cty + string(os.PathSeparator) + constants.NmapIPv6PortFile + "." + constants.NmapFileExtion
		eextractNmapPortResult(nmapIPv6FN, portIPv6FN)

		// ipv4端口
		nmapIPv4FN := variables.RecordHisDir + constants.DNSTempFolder + "-" + variables.DNSDateSpec + string(os.PathSeparator) + cty + string(os.PathSeparator) + constants.NmapIPv4File + "." + constants.NmapFileExtion
		portIPv4FN := variables.RecordHisDir + constants.DNSTempFolder + "-" + variables.DNSDateSpec + string(os.PathSeparator) + cty + string(os.PathSeparator) + constants.NmapIPv4PortFile + "." + constants.NmapFileExtion
		eextractNmapPortResult(nmapIPv4FN, portIPv4FN)
	}
}

/*
	提取简单Nmap端口扫描结果
 */
func eextractNmapPortResult(nmapFile string, portAliveFile string) {
	timeNow := time.Now()
	util.LogRecord("Excuting: " +  nmapFile + " -> " + portAliveFile)

	var pSCMap = make(types.TPMSTPMSI64)		// 端口状态数量

	// 打开记录文件
	srcFile, err := os.Open(nmapFile)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	defer srcFile.Close()	// 该函数执行完毕退出前才会执行defer后的语句
	readFile := bufio.NewReader(srcFile)

	// 创建写出文件
	fw1, err1 := os.OpenFile(portAliveFile, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
	defer fw1.Close()
	if err1 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err1.Error()))
		os.Exit(1)
	}
	outFile := bufio.NewWriter(fw1) // 创建新的 Writer 对象

	// 遍历Nmap扫描结果
	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	for {
		if readedCount%variables.LogShowBigLag == 0 {
			readedCount = 0
			util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))
		}
		lineBytes, _, eR := readFile.ReadLine()
		if eR == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		lineString := string(lineBytes)

		// 不属于有效结果行
		if !strings.HasPrefix(lineString, constants.NmapSigLineStartHost) {
			continue
		}

		lineBytes, _, eR = readFile.ReadLine()
		if eR == io.EOF {
			break
		}
		readedCount++
		readedTotal++
		lineString = string(lineBytes)

		psList := strings.Split(strings.Split(lineString, constants.NmapSigResStartHost)[constants.NmapSigPortIndex], constants.NmapPortGap)

		// 遍历端口
		for _, ps := range psList {
			psl := strings.Split(ps, constants.NmapPSGap)
			// 端口不存在
			if _, ok := pSCMap[psl[constants.NmapPortIndex]]; !ok {
				scMap := make(types.TPMSI64)
				pSCMap[psl[constants.NmapPortIndex]] = scMap
			}
			pSCMap[psl[constants.NmapPortIndex]][psl[constants.NmapStatisIndex]]++
			pSCMap[psl[constants.NmapPortIndex]][constants.TotalTimesString]++

		}

	}
	util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow)/time.Second))

	// 保存结果到JSon
	jsonBytes, err := json.Marshal(pSCMap)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	_, err = outFile.WriteString(string(jsonBytes) + "\n")
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	outFile.Flush()

	util.LogRecord("Ending: " +  nmapFile + " -> " + portAliveFile)
}
