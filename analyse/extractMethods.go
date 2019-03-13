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
	"bytes"
	"fmt"
	"io"
	"os"
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

		zdnsDomainIPv4 := util.ZDNSJson2String(zdnsJsonBytes)

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

	util.LogRecord("Excuting: " + fileName + "->"  + fileNameNew)
}
