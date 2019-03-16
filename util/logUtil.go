/*
@File : logUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 11:39
*/

package util

import (
	"analysePDNSByMonth/variables"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

/*
	获得调用函数的函数名
 */
func GetNowFuncInfo() string {
	fileName, line, funcName := "???.go", 0, "???"
	pc, fileName, line, ok := runtime.Caller(2)
	if ok {
		funcName = runtime.FuncForPC(pc).Name()      		// main.foo
		funcName = filepath.Ext(funcName)            		// .foo
		funcName = strings.TrimPrefix(funcName, ".") 	// foo
		fileName = filepath.Base(fileName) 					// /full/path/basename.go => basename.go
	}
	return fmt.Sprintf("%s:%s():%d", fileName, funcName, line)
}

/*
	日志记录
 */
func LogRecord(info string) {
	log.SetFlags(log.Ldate|log.Ltime)
	if variables.LogShow {
		log.SetOutput(os.Stdout)
		log.Printf(GetNowFuncInfo() + "\t" + info)
	}
	if variables.LogFile {
		log.SetOutput(variables.LogWriter)
		log.Printf(GetNowFuncInfo() + "\t" + info)
	}
}

/*
	日志记录
 */
func LogRecordSimple(info string) {
	log.SetFlags(0)
	if variables.LogFile {
		log.SetOutput(variables.ResWriter)
		log.Printf(info)
	}
}
