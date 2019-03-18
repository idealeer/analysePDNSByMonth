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
	"os"
	"strconv"
	"strings"
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
	// 创建展示文件夹
	variables.IPv6TrendFolderName = variables.DNSFileResDir + constants.IPv6TrendFolderName + "-" + variables.DNSDateSpec + string(os.PathSeparator)
	fg, err = os.Stat(variables.IPv6TrendFolderName)
	if err != nil {
		ec := os.Mkdir(variables.IPv6TrendFolderName, os.ModePerm)
		if ec != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
			os.Exit(1)
		}
	}
	// 创建v4展示文件夹
	variables.ShowV4FolderName = variables.IPv6TrendFolderName + constants.ShowV4FolderName + string(os.PathSeparator)
	fg, err = os.Stat(variables.ShowV4FolderName)
	if err != nil {
		ec := os.Mkdir(variables.ShowV4FolderName, os.ModePerm)
		if ec != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", err.Error())
			os.Exit(1)
		}
	}
	// 创建v6展示文件夹
	variables.ShowV6FolderName = variables.IPv6TrendFolderName + constants.ShowV6FolderName + string(os.PathSeparator)
	fg, err = os.Stat(variables.ShowV6FolderName)
	if err != nil {
		ec := os.Mkdir(variables.ShowV6FolderName, os.ModePerm)
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
	历史中间文件保存文件夹
 */
func PrepareHisRecordDir(fileDir string) {
	fg, err := os.Stat(fileDir)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-hisRecord-dir parm]", err.Error()))
		os.Exit(1)
	}
	if fg.IsDir() {		// 目录
		variables.RecordHisDir = util.NormalFileDir(fileDir)
	} else {			// 文件
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-hisRecord-dir parm]", err.Error()))
		os.Exit(1)
	}
}

/*
	日志准备
 */
func PrepareSimpleLog() {
	variables.ResFileName = GetResFileName(time.Now().Format(fmt.Sprintf("%s-%s", constants.ResFileName, constants.DateFormat)), constants.LogExtion)
	fw, err := os.OpenFile(variables.ResFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755) // 打开或创建文件
	variables.ResWriter = fw
	//defer variables.LogWriter.Close()	// 不能关闭
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s", err.Error()))
		os.Exit(1)
	}
}

/*
	分析结果
 */
func PrepareAnaRes(fileDir string, cnp int, cnz int, ctys string) {
	// iso中文国家名文件
	fg, err := os.Stat(fileDir)
	if err != nil {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-iso-dir parm]", err.Error()))
		os.Exit(1)
	}
	if fg.IsDir() {		// 目录
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-iso-dir parm]", err.Error()))
		os.Exit(1)
	} else {			// 文件
		variables.IsoCNNameFile = fileDir
	}
	// 中国人口数量
	if cnp < 0 {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-cnp parm]", err.Error()))
		os.Exit(1)
	} else {
		variables.CPLNum = int64(cnp) * constants.YYTimes
	}
	// 中国网民数量
	if cnz < 0 {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-cnz parm]", err.Error()))
		os.Exit(1)
	} else {
		variables.CNZNum = int64(cnz) * constants.YYTimes
	}

	util.GetISOCNMap(variables.IsoCNNameFile)

	// 国家列表
	if ctys == "" {
		util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-ctys parm]", err.Error()))
		os.Exit(1)
	} else {
		ctyList := strings.Split(ctys, ",")
		for _, cty := range ctyList {
			if _, ok := variables.IsoCNNameMap[cty]; !ok && cty != constants.TotalTimesString {
				util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-ctys parm], not %s", err.Error(), cty))
				os.Exit(1)
			}
		}
		variables.Countrys = ctys
	}

	variables.TotalMonthNum = util.GetMonthNums(variables.DNSDateBefore, variables.DNSDateSpec)
	variables.TotalDayNum = variables.TotalMonthNum * 30
}

/*
	域名v4地址字典文件
 */
func PrepareD4File(fileDir string) {
	if fileDir != "" {
		fg, err := os.Stat(fileDir)
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-d4-file parm]", err.Error()))
			os.Exit(1)
		}
		if fg.IsDir() { // 目录
			util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-d4-file parm]", err.Error()))
			os.Exit(1)
		} else { // 文件
			variables.D4FileName = fileDir
		}
	}
}

/*
	ip地理字典文件
 */
func PrepareV46GeoFile(v4File string, v6File string) {
	if v4File != "" {
		fg, err := os.Stat(v4File)
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-v4Geo-file parm]", err.Error()))
			os.Exit(1)
		}
		if fg.IsDir() { // 目录
			util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-v4Geo-file parm]", err.Error()))
			os.Exit(1)
		} else { // 文件
			variables.V4GeoFileName = v4File
		}
	}
	if v6File != "" {
		fg, err := os.Stat(v6File)
		if err != nil {
			util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-v6Geo-file parm]", err.Error()))
			os.Exit(1)
		}
		if fg.IsDir() { // 目录
			util.LogRecord(fmt.Sprintf("Error: %s\tPlease add the correct [-v6Geo-file parm]", err.Error()))
			os.Exit(1)
		} else { // 文件
			variables.V6GeoFileName = v6File
		}
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
	}
}

/*
	递增递减
 */
func PrepareOrder(inc bool, dec bool) []string {
	if (inc || dec) == false {
		fmt.Printf("Error: Please add [-inc] or [-dec]\n")
		os.Exit(1)
	}
	if (inc && dec) == true {
		fmt.Printf("Error: Please not add [-inc] and [-dec]\n")
		os.Exit(1)
	}
	var mList = make([]string, 0)
	if inc {
		if variables.DNSDateSpec > variables.DNSDateEnd {
			fmt.Printf("Error: Please add the correct [-date parm] and [-date-end parm]\n")
			os.Exit(1)
		}
		dateInt, _:= strconv.Atoi(variables.DNSDateSpec)
		dateEndInt, _:= strconv.Atoi(variables.DNSDateEnd)
		sy := dateInt / 100
		sm := dateInt % 100
		ey := dateEndInt / 100
		em := dateEndInt % 100
		mList, _ = util.GetSpecYMsByYM(sy, sm, ey, em)
		return mList
	}
	if dec {
		if variables.DNSDateSpec < variables.DNSDateEnd {
			fmt.Printf("Error: Please add the correct [-date parm] and [-date-end parm]\n")
			os.Exit(1)
		}
		dateInt, _:= strconv.Atoi(variables.DNSDateEnd)
		dateEndInt, _:= strconv.Atoi(variables.DNSDateSpec)
		sy := dateInt / 100
		sm := dateInt % 100
		ey := dateEndInt / 100
		em := dateEndInt % 100
		mList, _ = util.GetSpecYMsByYM(sy, sm, ey, em)
		for i, j := 0, len(mList)-1; i < j; i, j = i+1, j-1 {
			mList[i], mList[j] = mList[j], mList[i]
		}
		return mList
	}
	return mList
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
func PrepareDate(date string, dateBefore string, dateEnd string) {
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
	if util.MatchRegexp(constants.DateRegexp, dateEnd) {
		variables.DNSDateEnd = dateEnd
	} else{
		fmt.Printf("Error: Please add the correct [-date-end parm], like %s\n", constants.DateExample)
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
