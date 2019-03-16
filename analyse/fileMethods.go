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
	"bytes"
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
	获得先前结果文件夹中的完整文件名
 */
func GetBeforeResFileName(fileName string, fileExtion string) string {
	return fmt.Sprintf("%s%s.%s", variables.ResBeforeDir, fileName, fileExtion)
}

/*
	获得API结果文件夹中的完整文件名
 */
func GetApiResFileName(fileName string, fileExtion string) string {
	return fmt.Sprintf("%s%s.%s", variables.ApiResDir, fileName, fileExtion)
}

/*
	判断是否是DNS文件夹
 */
func IsTheDNSFolder(fi os.FileInfo) bool {
	return fi.IsDir() && util.MatchRegexp(constants.DNSFolerReg, fi.Name()) && strings.HasPrefix(fi.Name(), variables.DNSDateSpec)
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

	var dnsRecordNew bytes.Buffer

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
		if len(dnsRecordList) != constants.DataSigLen {
			util.LogRecord(fmt.Sprintf("Error record in %s: %s", fileName, lineString))
			continue
		}
		dnsRecordDomain := util.GetSignifcantDomainData(dnsRecordList[constants.ODomainIndex])
		dnsRecordCount := dnsRecordList[constants.OCountIndex]	// util.GetSignifcantCountData(dnsRecordList[constants.OCountIndex])
		dnsRecordIPv6 := dnsRecordList[constants.OIPv6Index]	// util.GetSignifcantIPv6Data(dnsRecordList[constants.OIPv6Index])
		//dnsRecordNew := fmt.Sprintf("%s\t%s\t%s", dnsRecordDomain, dnsRecordCount, dnsRecordIPv6)

		dnsRecordNew.WriteString(dnsRecordDomain)
		dnsRecordNew.WriteByte('\t')
		dnsRecordNew.WriteString(dnsRecordCount)
		dnsRecordNew.WriteByte('\t')
		dnsRecordNew.WriteString(dnsRecordIPv6)
		dnsRecordNew.WriteByte('\n')

		_, err = outWFile.WriteString(dnsRecordNew.String())
		dnsRecordNew.Reset()

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

/*
	反转域名到合并文件
  */
func ReverseDomain2UnionFile(fileName string, fileNameNew string) {
	timeNow := time.Now()
	util.LogRecord(fmt.Sprintf("Excuting: %s -> %s", fileName, fileNameNew))

	// 合并后的文件不存在，则进行合并
	if util.FileIsNotExist(fileNameNew) {
		fw, err := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		// 打开源文件
		srcFile, err := os.Open(fileName)
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		defer srcFile.Close()	// 该函数执行完毕退出前才会执行defer后的语句
		br := bufio.NewReader(srcFile)

		var readedCount uint64 = 0
		var readedTotal uint64 = 0

		var dnsRecordNew bytes.Buffer

		for {
			if readedCount % variables.LogShowBigLag == 0 {
				readedCount = 0
				util.LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))
			}
			lineBytes, _, eR := br.ReadLine()
			if eR == io.EOF {
				break
			}
			readedCount++
			readedTotal++

			lineString := string(lineBytes)
			dnsRecordList := strings.Split(lineString, "\t")
			dnsRecordCount := dnsRecordList[constants.OCountIndex]	// util.GetSignifcantCountData(dnsRecordList[constants.OCountIndex])
			dnsRecordDomain := util.GetSignifcantDomainData(dnsRecordList[constants.ODomainIndex])
			dnsRecordIPv6 := dnsRecordList[constants.OIPv6Index]	// util.GetSignifcantIPv6Data(dnsRecordList[constants.OIPv6Index])
			//dnsRecordNew := fmt.Sprintf("%s\t%s\t%s", dnsRecordDomain, dnsRecordCount, dnsRecordIPv6)

			dnsRecordNew.WriteString(dnsRecordDomain)
			dnsRecordNew.WriteByte('\t')
			dnsRecordNew.WriteString(dnsRecordCount)
			dnsRecordNew.WriteByte('\t')
			dnsRecordNew.WriteString(dnsRecordIPv6)
			dnsRecordNew.WriteByte('\n')

			_, err = outWFile.WriteString(dnsRecordNew.String())
			dnsRecordNew.Reset()

			if err != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
				continue
			}
			outWFile.Flush()

		}


		util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord(fmt.Sprintf("Ending: %s -> %s", fileName, fileNameNew))
}

/*
	单个文件合并
 */
func unionDNSFileMul(fileName string, fileNameNew string, res chan<- string) {
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

	fw, err1 := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755) // 打开或创建文件
	defer fw.Close()
	if err1 != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err1.Error()))
		os.Exit(1)
	}
	outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

	var dnsRecordNew bytes.Buffer

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
		if len(dnsRecordList) != 3 {
			util.LogRecord(fmt.Sprintf("Error record in %s: %s", fileName, lineString))
			continue
		}

		dnsRecordDomain := util.GetSignifcantDomainData(dnsRecordList[constants.ODomainIndex])
		dnsRecordCount := dnsRecordList[constants.OCountIndex]	// util.GetSignifcantCountData(dnsRecordList[constants.OCountIndex])
		dnsRecordIPv6 := dnsRecordList[constants.OIPv6Index]	// util.GetSignifcantIPv6Data(dnsRecordList[constants.OIPv6Index])
		//dnsRecordNew := fmt.Sprintf("%s\t%s\t%s", dnsRecordDomain, dnsRecordCount, dnsRecordIPv6)

		dnsRecordNew.WriteString(dnsRecordDomain)
		dnsRecordNew.WriteByte('\t')
		dnsRecordNew.WriteString(dnsRecordCount)
		dnsRecordNew.WriteByte('\t')
		dnsRecordNew.WriteString(dnsRecordIPv6)
		dnsRecordNew.WriteByte('\n')

		_, err = outWFile.WriteString(dnsRecordNew.String())
		dnsRecordNew.Reset()

		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			continue
		}
		outWFile.Flush()

	}

	res <- fileName
	//LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))
	//LogRecord("Ending: " + fileName)
}

/*
	合并文件
  */
func UnionDNSFileOnDirMul(fileDir string, fileNameNew string) {
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
		//outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

		var returnFolder = make(chan string) 	// 并发合并文件

		// 外层文件夹
		folderList, e := ioutil.ReadDir(fileDir)
		if e != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		for _, folderInfo := range folderList {

			readedCount := 0
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
						readedCount++
						fileName := folderName + fi.Name()
						go unionDNSFileMul(fileName, fileNameNew, returnFolder) // 合并文件
					}
				}

				// 并发输出
				for i := 0; i < readedCount; i++ {
					dnsRecordNewTemp := <-returnFolder
					util.LogRecord(fmt.Sprintf("ending: %s, cost: %ds", dnsRecordNewTemp, time.Now().Sub(timeNow)/time.Second))
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

