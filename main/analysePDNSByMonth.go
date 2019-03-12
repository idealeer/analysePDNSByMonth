/*
@File : hello
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-01-25 12:58
*/
package main

import (
	"analysePDNSByMonth/analyse"
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/util"
	"flag"
	"fmt"
	"os"
	"time"
)

// 参数
var (
	excute     		int    	// 任务
	function   		int    	// 功能
	mmdb       		string 	// mmdb数据库
	date       		string 	// 指定日期月份
	dateBefore		string	// 先前日期月份
	dateEnd			string	// 截止日期月份
	inc				bool	// 月份递增
	dec				bool 	// 月份递减
	logShow    		bool   	// log输出到控制台
	logFile    		bool   	// log记录到日志文件
	logLevel   		int    	// log等级
	ips        		string 	// ip
	ipFile     		string 	// ip文件
	domains    		string 	// 域名
	domainFile 		string 	// 域名文件
	sourceDir  		string 	// 源目录
	destyDir   		string 	// 合并文件目录
	zdns       		string 	// zdns可执行文件
	threads    		int    	// 并发数
	testFile   		string 	// 测试文件
	topN	   		int    	// topN显示
	beforeResDir	string	// 已有结果文件夹
	apiResDir		string	// 历史结果-API类型文件夹
	d4File			string  // 域名、v4地址字典库
	v4GeoFile		string	// v4地理库
	v6GeoFile		string	// v6地理库
	hisRecordDir	string  // 历史结果保存文件夹
)

func init() {
	// 一级命令
	flag.IntVar(&excute, "excute", int(constants.CmdDefault),
		fmt.Sprintf("%d\t%s\n", constants.CmdAnalyse, "统计PDNS数据，进行新的分析前请自行处理临时数据，以防临时数据错误")+
			fmt.Sprintf("%d\t%s\n", constants.CmdMMDB, "查询MaxMind数据库地理信息")+
			fmt.Sprintf("%d\t%s\n", constants.CmdUnionFile, "合并指定目录下的文件")+
			fmt.Sprintf("%d\t%s\n", constants.CmdNS, "查询IPv4地址")+
			fmt.Sprintf("%d\t%s\n", constants.CmdTest, "测试")+
			fmt.Sprintf("%d\t%s\n", constants.CmdApi2Json, "API结果转Json")+
			fmt.Sprintf("%d\t%s", constants.CmdDefault, "什么也没做(默认)"))

	// 二级命令
	flag.IntVar(&function, "function", int(constants.CCmdDefault),
		fmt.Sprintf("%d\t%s\n", constants.CCmdAll, "统计PDNS数据:全部功能\t\t(须指定:-excute [0])")+

			fmt.Sprintf("%d\t%s\n", constants.CCmdUnionDNS, "统计PDNS数据:合并DNS记录\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdUniqDomain, "统计PDNS数据:去重域名\t\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdNSIPv4, "统计PDNS数据:查询IPv4地址\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdUnionDNSV4, "统计PDNS数据:合并DNS记录&V4地址\t(须指定:-excute [0])")+

			fmt.Sprintf("%d\t%s\n", constants.CCmdUniqTLD, "统计PDNS数据:去重TLD\t\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdAnaTLDTimes, "统计PDNS数据:分析TLD请求次数\t(须指定:-excute [0])")+

			fmt.Sprintf("%d\t%s\n", constants.CCmdGetGeo, "统计PDNS数据:获得地理信息\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdUniqDomainByGeo, "统计PDNS数据:根据地理去重域名\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdUniqIPv6ByGeo, "统计PDNS数据:根据地理去重IPv6\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdUniqSLDByGeo, "统计PDNS数据:根据地理去重SLD\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdAnaDNSTimesByGeo, "统计PDNS数据:分析DNS请求次数\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdAnaDomainByGeo, "统计PDNS数据:分析活跃域名\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdAnaIPv6ByGeo, "统计PDNS数据:分析活跃IPv6\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdAnaSLDByGeo, "统计PDNS数据:分析活跃SLD\t(须指定:-excute [0])")+
			fmt.Sprintf("%d\t%s\n", constants.CCmdAnaSLDTimesByGeo, "统计PDNS数据:分析SLD请求次数\t(须指定:-excute [0])")+

			fmt.Sprintf("%d\t%s\n", constants.CCmdUnionBeforeRes, "统计PDNS数据:合并历史结果文件\t(须指定:-excute [0])")+

			fmt.Sprintf("%d\t%s", constants.CCmdDefault, "什么也没做(默认)"))

	flag.StringVar(&mmdb, "mmdb", "",
		fmt.Sprintf("%s", "mmdb数据库路径"))

	flag.StringVar(&date, "date", constants.DateExample,
		fmt.Sprintf("%s", "指定日期月份"))

	flag.StringVar(&dateBefore, "date-before", constants.DateExample,
		fmt.Sprintf("%s", "先前日期月份"))

	flag.StringVar(&dateEnd, "date-end", constants.DateExample,
		fmt.Sprintf("%s", "结束日期月份"))

	flag.BoolVar(&inc, "inc", false,
		fmt.Sprintf("%s\n", "递增为假"))

	flag.BoolVar(&dec, "dec", false,
		fmt.Sprintf("%s\n", "递减为假"))

	flag.BoolVar(&logShow, "log-show", true,
		fmt.Sprintf("%s\n", "log输出到控制台(默认输出)") +
		fmt.Sprintf("-log-show=%t\t%s", constants.LogHide, "log不输出到控制台"))


	flag.BoolVar(&logFile, "log-file", true,
		fmt.Sprintf("%s\n", "log记录到日志文件(默认记录)") +
			fmt.Sprintf("-log-file=%t\t%s", constants.LogNoFile, "log不记录到日志文件"))

	flag.IntVar(&logLevel, "log-level", int(constants.LogLev3),
		fmt.Sprintf("%d\t%s\n", constants.LogLev1, "日志等级：极简单")+
			fmt.Sprintf("%d\t%s\n", constants.LogLev2, "日志等级：简单")+
			fmt.Sprintf("%d\t%s\n", constants.LogLev3, "日志等级：一般")+
			fmt.Sprintf("%d\t%s\n", constants.LogLev4, "日志等级：详细")+
			fmt.Sprintf("%d\t%s", constants.LogLev5, "日志等级：极详细"))

	flag.StringVar(&ips, "ips", "",
		fmt.Sprintf("%s", "ip地址字符串s, ','分割"))

	flag.StringVar(&ipFile, "ip-file", "",
		fmt.Sprintf("%s", "ip文件"))

	flag.StringVar(&domains, "domains", "",
		fmt.Sprintf("%s", "域名字符串s, ','分割"))

	flag.StringVar(&domainFile, "domain-file", "",
		fmt.Sprintf("%s", "域名文件"))

	flag.StringVar(&sourceDir, "source-dir", "",
		fmt.Sprintf("%s", "源目录(必须指定)"))

	flag.StringVar(&destyDir, "desty-dir", "",
		fmt.Sprintf("%s", "合并文件目录"))

	flag.StringVar(&zdns, "zdns", "",
		fmt.Sprintf("%s", "zdns可执行文件路径"))

	flag.IntVar(&threads, "threads", 1000,
		fmt.Sprintf("ZDNS查询IPv4并发数"))

	flag.StringVar(&testFile, "test-file", "",
		fmt.Sprintf("%s", "测试文件路径"))

	flag.IntVar(&topN, "topn", 50,
		fmt.Sprintf("topN显示条数"))

	flag.StringVar(&beforeResDir, "beforeRes-dir", "",
		fmt.Sprintf("%s", "已有结果目录(待合并结果文件)"))

	flag.StringVar(&apiResDir, "apiRes-dir", "",
		fmt.Sprintf("%s", "历史结果API类型文件夹"))

	flag.StringVar(&d4File, "d4-file", "",
		fmt.Sprintf("%s", "域名v4地址字典文件"))

	flag.StringVar(&v4GeoFile, "v4Geo-file", "",
		fmt.Sprintf("%s", "v4地理库文件"))

	flag.StringVar(&v6GeoFile, "v6Geo-file", "",
		fmt.Sprintf("%s", "v6地理库文件"))

	flag.StringVar(&hisRecordDir, "hisRecord-dir", "",
		fmt.Sprintf("%s", "历史中间结果保存文件夹"))

	flag.Usage = usage // 改变默认的usage
}

func main() {

	flag.Parse()

	// 初始化
	analyse.PrepareDate(date, dateBefore, dateEnd)
	analyse.PrepareFileDir(sourceDir)
	analyse.PrepareHisRecordDir(hisRecordDir)
	analyse.PrepareLog(logShow, logFile, int8(logLevel))

	// 命令执行、必须提供指定参数，如何实现
	var cmd uint8 = uint8(excute)
	var ccmd uint8 = uint8(function)

	timeNow := time.Now()
	util.LogRecord("Excuting:")

	switch cmd {
	case constants.CmdAnalyse:
		analyse.PrepareBeforeResFile(util.NormalFileDir(beforeResDir) + constants.DNSResFolder + "-" + dateBefore)
		analyse.PrepareD4File(d4File)
		analyse.PrepareV46GeoFile(v4GeoFile, v6GeoFile)
		analyse.PrepareMaxMind(mmdb)
		analyse.PrepareZDNS(zdns, threads)
		analyse.PrepareTopN(topN)
		analyse.Analyse(ccmd)
		if ccmd == constants.CCmdAll || (ccmd >= constants.CCmdGetGeo && ccmd <= constants.CCmdAnaSLDTimesByGeo) {
			analyse.EndReserveResAndTemp()
		}
	case constants.CmdMMDB:
		analyse.PrepareMaxMind(mmdb)
		analyse.GetIPsGeoByMM(ips, ipFile)
	case constants.CmdUnionFile:
		analyse.UnionFiles(destyDir)
	case constants.CmdNS:
		analyse.PrepareZDNS(zdns, threads)
		analyse.ZDNSLookUpIPByDomain(domains, domainFile)
	case constants.CmdTest:
		analyse.PrepareMaxMind(mmdb)
		analyse.GetGeoPercentByFile(testFile)
	case constants.CmdApi2Json:
		analyse.PrepareAPIResFile(apiResDir)
		//analyse.PrepareDate(date, dateBefore)
		analyse.ApiRes2JsonRes()
	case constants.CmdAnalyseMul:

		timeNow1 := time.Now()

		var mList = make([]string, 0)
		mList = analyse.PrepareOrder(inc, dec)

		for _, ym := range mList {
			util.LogRecord("Excuting: " + ym)

			analyse.PrepareDate(ym, dateBefore, dateEnd)
			analyse.PrepareFileDir(sourceDir)
			analyse.PrepareLog(logShow, logFile, int8(logLevel))

			analyse.PrepareBeforeResFile(util.NormalFileDir(beforeResDir) + constants.DNSResFolder + "-" + dateBefore)
			analyse.PrepareD4File(d4File)
			analyse.PrepareV46GeoFile(v4GeoFile, v6GeoFile)
			analyse.PrepareMaxMind(mmdb)
			analyse.PrepareZDNS(zdns, threads)
			analyse.PrepareTopN(topN)
			analyse.Analyse(ccmd)

			dateBefore = ym

			analyse.EndReserveResAndTemp()

			util.LogRecord(fmt.Sprintf("cost: %s", util.CostTime(timeNow1)))
			util.LogRecord("Task completed!!! " + ym)

			if ym != mList[len(mList) - 1] {
				analyse.EndLog()
			}
		}

	default:
		util.LogRecord("什么也没做\tPlease add the correct [-excute parm]")
		usage()
	}

	util.LogRecord(fmt.Sprintf("cost: %s", util.CostTime(timeNow)))
	util.LogRecord("Task completed!!!\n\n\n\n\n")

	analyse.EndMaxMind()
	analyse.EndLog()
}

func usage() {
	fmt.Fprintf(os.Stderr, `analysePDNSByMonth version: analysePDNSByMonth/1.0
Usage: analysePDNSByMonth <-source-dir sourceDir> <-mmdb mmdbFile> [-excute task] [-function function] [-date dateYearMonth] [-log-show logShow|logNotShow] [-log-file logFile|logNotFile] [-log-level logLevel] [-ips ip] [-desty-dir destFile]

Requirement:
	-source-dir sourceDir

Options:
`)

	flag.PrintDefaults()

	fmt.Fprintf(os.Stderr, `
Example:
	analysePDNSByMonth -source-dir source-dir -mmdb -zdns zdns -beforeRes-dir before-dir -date 201902 -date-before 201901 -excute 0 -function 0		分析V46地理的全部数据

`)
}