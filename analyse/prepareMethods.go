/*
@File : prepareMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 12:02
*/

package analyse

import (
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/util"
	"analysePDNSByMonth/variables"
	"fmt"
	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
	"log"
	"os"
	"time"
)

/*
	文件夹准备
 */
func PrepareFileDir(fileDir string) {
	fg, err := os.Stat(fileDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\tPlease add the correct [-source-dir parm]", err.Error())
		os.Exit(1)
	}
	if fg.IsDir() {		// 目录
		variables.DNSFileDir = util.NormalFileDir(fileDir)
	} else {			// 文件
		variables.DNSFileDir = util.GetParDir(fileDir)
		variables.DNSFileName = fileDir
	}
	// 创建临时文件夹
	variables.DNSFileTempDir = variables.DNSFileDir + constants.DNSTempFolder + "-" + variables.DNSDateSpec + string(os.PathSeparator)
	fg, err = os.Stat(variables.DNSFileTempDir)
	if err != nil {
		ec := os.Mkdir(variables.DNSFileTempDir, os.ModePerm)
		if ec != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
			os.Exit(1)
		}
	}
	// 创建结果文件夹
	variables.DNSFileResDir = variables.DNSFileDir + constants.DNSResFolder + "-" + variables.DNSDateSpec + string(os.PathSeparator)
	fg, err = os.Stat(variables.DNSFileResDir)
	if err != nil {
		ec := os.Mkdir(variables.DNSFileResDir, os.ModePerm)
		if ec != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
			os.Exit(1)
		}
	}
}

/*
	先前结果文件准备
 */
func PrepareBeforeResFile(fileDir string) {
	fg, err := os.Stat(fileDir)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-beforeRes-dir parm]", err.Error()))
		os.Exit(1)
	}
	if fg.IsDir() {		// 目录
		variables.ResBeforeDir = util.NormalFileDir(fileDir)
	} else {			// 文件
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-beforeRes-dir parm]", err.Error()))
		os.Exit(1)
	}
}

/*
	历史结果文件API类型
 */
func PrepareAPIResFile(fileDir string) {
	fg, err := os.Stat(fileDir)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-apiRes-dir parm]", err.Error()))
		os.Exit(1)
	}
	if fg.IsDir() {		// 目录
		variables.ApiResDir = util.NormalFileDir(fileDir)
	} else {			// 文件
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-apiRes-dir parm]", err.Error()))
		os.Exit(1)
	}
}

/*
	日志准备
 */
func PrepareLog(logShow bool, logFile bool, logShowLev int8) {
	variables.LogShow = logShow			// 控制台输出与否
	variables.LogFile = logFile			// 日志记录与否
	if logShowLev >= constants.LogLevMax || logShowLev < constants.LogLev1 {
		fmt.Fprintf(os.Stderr, "Error: %s", "LogLev out of range.")
		os.Exit(1)
	}
	variables.LogShowLev = logShowLev	// 日志等级
	variables.LogShowBigLag = constants.LogBigNum * util.Pow(10, variables.LogShowLev)
	variables.LogShowSmlLag = constants.LogSmlNum * util.Pow(10, variables.LogShowLev)
	if logFile {
		variables.LogFileName = GetResFileName(time.Now().Format(fmt.Sprintf("%s-%s", constants.LogFileName, constants.DateFormat)), constants.LogExtion)
		fw, err := os.OpenFile(variables.LogFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755) // 打开或创建文件
		variables.LogWriter = fw
		//defer variables.LogWriter.Close()	// 不能关闭
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
			os.Exit(1)
		}
		log.SetFlags(log.Ldate|log.Ltime)
	}
}

/*
	MaxMind数据库准备
 */
func PrepareMaxMind(fileName string) {
	fg, err := os.Stat(fileName)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\nPlease add the correct [-mmdb parm](mmdb file)", err.Error()))
		os.Exit(1)
	}
	if fg.IsDir() {
		util.LogRecord(fmt.Sprintf("Error: Please add the correct [-mmdb parm](mmdb file)"))
		os.Exit(1)
	}

	variables.MaxMindDBName = fileName

	// 打开maxminddb数据库
	geoDB, eO := geoip2.Open(variables.MaxMindDBName)
	if eO != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", eO.Error()))
		os.Exit(1)
	}
	variables.MaxMindReader = geoDB
}

/*
	日期月份准备
 */
func PrepareDate(date string, dateBefore string) {
	if util.MatchRegexp(constants.DateRegexp, date) {
		variables.DNSDateSpec = date
	} else{
		fmt.Printf("Error: Please add the correct [-date parm], like %s\n", constants.DateExample)
		os.Exit(1)
	}
	if util.MatchRegexp(constants.DateRegexp, dateBefore) {
		variables.DNSDateBefore = dateBefore
	} else{
		fmt.Printf("Error: Please add the correct [-date-before parm], like %s\n", constants.DateExample)
		os.Exit(1)
	}
}

/*
	dns解析文件准备
 */
func PrepareDNSConfig() {
	variables.DNSConfig, _ = dns.ClientConfigFromFile(constants.ResolvFile)
}

/*
	ZDNS准备
 */
func PrepareZDNS(fileName string, thread int) {
	fg, err := os.Stat(fileName)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-zdns parm]", err.Error()))
		os.Exit(1)
	}
	if fg.IsDir() {		// 目录
		util.LogRecord(fmt.Sprintf("Error: Please add the correct [-zdns parm](zdns excute file)"))
		os.Exit(1)
	} else {			// 文件
		variables.ZDNSExeFileName = fileName
	}
	if thread < 0 {
		util.LogRecord(fmt.Sprintf("Error: Please add the correct [-threads parm](>0)"))
		os.Exit(1)
	} else{
		variables.ZDNSThreads = thread
	}
}

/*
	准备topN条数
 */
func PrepareTopN(topN int){
	if topN < 0 {
		util.LogRecord(fmt.Sprintf("Error: Please add the correct [-topn parm](>0)"))
		os.Exit(1)
	} else{
		variables.TopNDomains = int64(topN)
	}
}
