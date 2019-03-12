/*
@File : endMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 14:39
*/

package analyse

import (
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/util"
	"analysePDNSByMonth/variables"
	"fmt"
	"os"
	"strings"
	"time"
)

/*
	日志记录收尾
 */
func EndLog() {
	if variables.LogWriter != nil {
		variables.LogWriter.Close()
	}
}

/*
	MaxMind收尾
 */
func EndMaxMind() {
	if variables.MaxMindReader != nil {
		variables.MaxMindReader.Close()
	}
}

/*
	保存结果文件和中间文件
 */
func EndReserveResAndTemp() {
	timeNow := time.Now()
	util.LogRecord("Excuting:")

	// 保存结果文件
	resBeforeDir := util.GetParDir(strings.TrimRight(variables.ResBeforeDir, string(os.PathSeparator))) + constants.DNSResFolder + "-" + variables.DNSDateSpec
	err := os.Rename(variables.DNSFileResDir, resBeforeDir)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Errors: %s", err.Error()))
		os.Exit(1)
	} else {
		util.LogRecord(fmt.Sprintf("move ok: %s -> %s", variables.DNSFileResDir, resBeforeDir))
	}

	//// 保存临时文件，创建临时文件夹
	tmpDir := variables.RecordHisDir + constants.DNSTempFolder + "-" + variables.DNSDateSpec + string(os.PathSeparator)
	_, err1 := os.Stat(tmpDir)
	if err1 != nil {
		ec := os.Mkdir(tmpDir, os.ModePerm)
		if ec != nil {
			util.LogRecord(fmt.Sprintf("Errors: %s", err1.Error()))
			os.Exit(1)
		}
	}
	// 保存中间文件GeoPDNS
	tmpDirFile := tmpDir + constants.DNSFileV6GeoV4GeoName
	err3 := os.Rename(variables.DNSFileV6GeoV4GeoName, tmpDirFile)
	if err3 != nil {
		util.LogRecord(fmt.Sprintf("Errors: %s", err3.Error()))
		os.Exit(1)
	} else {
		util.LogRecord(fmt.Sprintf("move ok: %s -> %s", variables.DNSFileV6GeoV4GeoName, tmpDirFile))
	}
	// 删除剩余中间文件
	err4 := os.RemoveAll(variables.DNSFileTempDir)
	if err4 != nil {
		util.LogRecord(fmt.Sprintf("Errors: %s", err4.Error()))
		os.Exit(1)
	} else {
		util.LogRecord(fmt.Sprintf("remove ok: %s", variables.DNSFileTempDir))
	}

	//// 删除原始记录文件
	rmFolder := ""
	for i := 1; i <= 31; i++ {
		rmFolder = fmt.Sprintf("%s%s%02d", variables.DNSFileDir, variables.DNSDateSpec, i)
		err5 := os.RemoveAll(rmFolder)
		if err5 != nil {
			util.LogRecord(fmt.Sprintf("Errors: %s", err5.Error()))
			os.Exit(1)
		}
	}
	util.LogRecord(fmt.Sprintf("remove ok: %s", fmt.Sprintf("%s%s%", variables.DNSFileDir, variables.DNSDateSpec)))

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: ")
}
