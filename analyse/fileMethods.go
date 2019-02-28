/*
@File : fileMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-13 13:54
*/

package analyse

import (
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/util"
	"analysePDNSByMonth/variables"
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

/*
	获得临时文件夹中的完整文件名
 */
func GetTmpFileName(fileName string, fileExtion string) string {
	return fmt.Sprintf("%s%s.%s", variables.DNSFileTempDir, fileName, fileExtion)
}

/*
	获得结果文件夹中的完整文件名
 */
func GetResFileName(fileName string, fileExtion string) string {
	return fmt.Sprintf("%s%s.%s", variables.DNSFileResDir, fileName, fileExtion)
}

/*
	判断是否是DNS文件夹
 */
func IsTheDNSFolder(fi os.FileInfo) bool {
	return fi.IsDir() && util.MatchRegexp(constants.DNSFolerReg, fi.Name())
}

/*
	判断是否是DNS文件
 */
func IsTheDNSFile(fi os.FileInfo) bool {
	return !fi.IsDir() && util.MatchRegexp(constants.DNSFileReg, fi.Name())
}

/*
	单个文件合并
 */
func unionDNSFile(fileName string, outWFile *bufio.Writer) {
	//timeNow := time.Now()
	//LogRecord("Excuting: " + fileName)

	// 打开源文件
	srcFile, err := os.Open(fileName)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		return
	}
	defer srcFile.Close()	// 该函数执行完毕退出前才会执行defer后的语句
	br := bufio.NewReader(srcFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0

	for {
		if readedCount % variables.LogShowBigLag == 0 {
			readedCount = 0
			//LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))
		}
		lineBytes, _, eR := br.ReadLine()
		if eR == io.EOF {
			break
		}
		readedCount++
		readedTotal++

		lineString := string(lineBytes)
		dnsRecordList := strings.Split(lineString, "\t")
		dnsRecordCount := util.GetSignifcantCountData(dnsRecordList[constants.OCountIndex])
		dnsRecordDomain := util.GetSignifcantDomainData(dnsRecordList[constants.ODomainIndex])
		dnsRecordIPv6 := util.GetSignifcantIPv6Data(dnsRecordList[constants.OIPv6Index])
		dnsRecordNew := fmt.Sprintf("%s\t%s\t%s", dnsRecordCount, dnsRecordDomain, dnsRecordIPv6)
		_, err = outWFile.WriteString(dnsRecordNew + "\n")
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			continue
		}
		outWFile.Flush()
	}

	//LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))
	//LogRecord("Ending: " + fileName)
}

/*
	合并文件
  */
func UnionDNSFileOnDir(fileDir string, fileNameNew string) {
	timeNow := time.Now()
	fileDir = util.NormalFileDir(fileDir)
	util.LogRecord(fmt.Sprintf("Excuting: %s -> %s", fileDir, fileNameNew))

	// 合并后的文件不存在，则进行合并
	if util.FileIsNotExist(fileNameNew) {
		fw, err := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 外层文件夹
		folderList, e := ioutil.ReadDir(fileDir)
		if e != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		for _, folderInfo := range folderList {
			if IsTheDNSFolder(folderInfo) {
				folderName := util.NormalFileDir(fileDir + folderInfo.Name())

				// 内层文件夹
				fileList, e := ioutil.ReadDir(folderName)
				if e != nil {
					util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
					os.Exit(1)
				}
				for _, fi := range fileList {
					if IsTheDNSFile(fi) {
						fileName := folderName + fi.Name()
						unionDNSFile(fileName, outWFile) // 合并文件
					}
				}
				util.LogRecord(fmt.Sprintf("ending: %s, cost: %ds", folderName, time.Now().Sub(timeNow)/time.Second))
			}
		}

		util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord(fmt.Sprintf("Ending: %s -> %s", fileDir, fileNameNew))
}
