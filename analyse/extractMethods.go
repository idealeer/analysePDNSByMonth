/*
@File : extractMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 08:35
*/

package analyse

import (
	"analysePDNSByMonth/util"
	"analysePDNSByMonth/variables"
	"bufio"
	"fmt"
	"io"
	"os"
	"time"
)

/*
	提取简单IPv4地址
 */
func getSimpleIPv4(fileName string, fileNameNew string){
	timeNow := time.Now()
	util.LogRecord("Excuting: " + fileName + "->"  + fileNameNew)

	if util.FileIsNotExist(fileNameNew) {
		fw, err := os.OpenFile(fileNameNew, os.O_RDWR|os.O_CREATE, 0755) // 打开或创建文件
		defer fw.Close()
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
			os.Exit(1)
		}
		outWFile := bufio.NewWriter(fw) // 创建新的 Writer 对象

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

			zdnsDomainIPv4 := util.ZDNSJson2String(zdnsJsonBytes)
			_, err = outWFile.WriteString(zdnsDomainIPv4 + "\n")
			if err != nil {
				util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
				continue
			}
			outWFile.Flush()
		}
		util.LogRecord(fmt.Sprintf("remaining: %d, cost: %ds", fileLines-readedTotal, time.Now().Sub(timeNow)/time.Second))
	} else {
		util.LogRecord(fmt.Sprintf("%s existed, cost: %ds", fileNameNew, time.Now().Sub(timeNow) / time.Second))
	}

	util.LogRecord("Excuting: " + fileName + "->"  + fileNameNew)
}
