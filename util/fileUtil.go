/*
@File : fileUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 12:24
*/

package util

import (
	"analysePDNSByMonth/variables"
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

/*
	标准化路径，末尾加分隔符
 */
func NormalFileDir(fileDir string) string {
	return strings.TrimRight(fileDir, string(os.PathSeparator)) + string(os.PathSeparator)
}

/*
	获得当前路径
 */
func GetCurPath() string {
	file, _ := exec.LookPath(os.Args[0])
	// 得到全路径，比如在windows下E:\\golang\\test\\a.exe
	path, _ := filepath.Abs(file)
	rst := filepath.Dir(path)
	return rst
}

/*
	获得父文件夹
 */
func GetParDir(fileName string) string {
	return filepath.Dir(fileName) + string(os.PathSeparator)
}

/*
	判断文件是否存在
 */
func FileIsNotExist(fileName string) bool {
	_, err := os.Stat(fileName)
	if err != nil {
		return true
	}
	return false
}

/*
	获得文件行数
 */
func GetLines(fileName string) uint64 {
	timeNow := time.Now()
	LogRecord(fmt.Sprintf("Excuting: %s", fileName))
	srcFile, err := os.Open(fileName)
	if err != nil {
		LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
	defer srcFile.Close()	// 该函数执行完毕退出前才会执行defer后的语句
	br := bufio.NewReader(srcFile)

	var readedCount uint64 = 0
	var readedTotal uint64 = 0
	for {
		if readedCount % variables.LogShowBigLag == 0 {
			readedCount = 0
			LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))
		}
		_, _, e := br.ReadLine()
		if e == io.EOF {
			break
		}
		readedCount++
		readedTotal++
	}

	LogRecord(fmt.Sprintf("readedtotal: %d, cost: %ds", readedTotal, time.Now().Sub(timeNow) / time.Second))
	LogRecord("Ending: " + fileName)
	return readedTotal
}
