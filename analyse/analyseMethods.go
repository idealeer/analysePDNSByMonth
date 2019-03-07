/*
@File : analyseMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-13 16:05
*/

package analyse

import (
	"analysePDNSByMonth/constants"
	"analysePDNSByMonth/util"
	"analysePDNSByMonth/variables"
	"fmt"
	"time"
)

func Analyse(ccmd uint8) {
	timeNow := time.Now()
	util.LogRecord("Excuting: ")

	switch {
	case ccmd >= constants.CCmdUnionDNS && ccmd <= constants.CCmdUnionDNSV4:
		analysePrepare(ccmd)
	case ccmd == constants.CCmdAll || (ccmd >= constants.CCmdGetGeo && ccmd < constants.CCmdDefault):
		analyseByGeo(ccmd)
	case ccmd == constants.CCmdUniqTLD || ccmd == constants.CCmdAnaTLDTimes:
		analyseTLD(ccmd)
	default:
		util.LogRecord("什么也没做\tPlease add the correct [-function parm]")
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: ")
}

////
/*
	分析准备
 */
func analysePrepare(ccmd uint8) {
	timeNow := time.Now()
	util.LogRecord("Excuting: ")

	switch ccmd {
	case constants.CCmdUnionDNS:
		unionDNSFiles()			// dns文件合并
	case constants.CCmdUniqDomain:
		uniqDomain()			// 去重域名用于nslookup
	case constants.CCmdNSIPv4:
		lpIPv4ByFileMulCH()		// 查询IPv4地址
	case constants.CCmdUnionDNSV4:
		unionDNSAndIPv4() 		// 合并DNS+V4地址
	default:
		util.LogRecord("什么也没做\tPlease add the correct [-function parm]")
	}

	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: ")
}

/*
	合并dns文件
 */
func unionDNSFiles() {
	if variables.DNSFileName == "" {		// 多个文件进行合并
		variables.DNSFileUnionName = GetTmpFileName(constants.DNSFileUnionName, constants.DNSFileTempExtion)		// 合并文件名称
		variables.DNSFileName = variables.DNSFileUnionName
		UnionDNSFileOnDir(variables.DNSFileDir, variables.DNSFileUnionName)		// 合并文件
	} else {								// 单个文件
		variables.DNSFileUnionName = variables.DNSFileName
		util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileUnionName))
	}
}

/*
	去重域名
 */
func uniqDomain() {
	unionDNSFiles()
	if variables.DNSFileUniqDomain == "" {
		variables.DNSFileUniqDomain = GetTmpFileName(constants.DNSFileUniqDomain, constants.DNSFileTempExtion)
		uniqueDomain(variables.DNSFileUnionName, variables.DNSFileUniqDomain)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileUniqDomain))
	}
}

/*
	查询IPv4地址
 */
func lpIPv4ByFileMulCH() {
	uniqDomain()
	if variables.DNSFileUniqDomainIPv4Detl == "" {
		variables.DNSFileUniqDomainIPv4Detl = GetTmpFileName(constants.DNSFileUniqDomainIPv4Detl, constants.DNSFileTempExtion)
		if util.FileIsNotExist(variables.DNSFileUniqDomainIPv4Detl) {
			zdnslookUpIPByFile(variables.DNSFileUniqDomain, variables.DNSFileUniqDomainIPv4Detl)
		} else {
			util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileUniqDomainIPv4Detl))
		}
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileUniqDomainIPv4Detl))
	}
	if variables.DNSFileUniqDomainIPv4 == "" {
		variables.DNSFileUniqDomainIPv4 = GetTmpFileName(constants.DNSFileUniqDomainIPv4, constants.DNSFileTempExtion)
		getSimpleIPv4(variables.DNSFileUniqDomainIPv4Detl, variables.DNSFileUniqDomainIPv4)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileUniqDomainIPv4))
	}
}

/*
	合并DNS+V4地址
 */
func unionDNSAndIPv4() {
	lpIPv4ByFileMulCH()
	if variables.DNSFileUnionV4Name == "" {
		variables.DNSFileUnionV4Name = GetTmpFileName(constants.DNSFileUnionV4Name, constants.DNSFileTempExtion)
		unionDNSRecordAndIP(variables.DNSFileUnionName, variables.DNSFileUniqDomainIPv4, variables.DNSFileUnionV4Name)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileUnionV4Name))
	}
}

//

//// 地理分析

func analyseByGeo(ccmd uint8) {
	timeNow := time.Now()
	util.LogRecord("Excuting: ")

	if ccmd >= constants.CCmdDefault || (ccmd < constants.CCmdGetGeo && ccmd != constants.CCmdAll) {
		util.LogRecord("什么也没做\tPlease add the correct [-function parm]")
		goto End
	}

	unionDNSFiles()			// dns文件合并
	uniqDomain()			// 去重域名用于nslookup
	lpIPv4ByFileMulCH()		// 查询IPv4地址
	unionDNSAndIPv4() 		// 合并DNS+V4地址

	switch ccmd {
	case constants.CCmdGetGeo:
		unionV6V4Geo() 						// 获得地理
	case constants.CCmdUniqDomainByGeo:
		uniqDomainByV6V4Geo() 				// 去重域名
	case constants.CCmdUniqIPv6ByGeo:
		uniqIPv6ByV6V4Geo() 				// 去重IPv6地址
	case constants.CCmdUniqSLDByGeo:
		uniqSLDByV6V4Geo() 					// 去重sld
	case constants.CCmdAnaDNSTimesByGeo:
		anlyseDNSTimesV6V4Geo() 			// 第二：分析dns次数
	case constants.CCmdAnaDomainByGeo:
		anlyseDomainV6V4Geo() 				// 第二：分析活跃域名
	case constants.CCmdAnaIPv6ByGeo:
		anlyseIPv6V6V4Geo() 				// 第三：分析活跃IPv6
	case constants.CCmdAnaSLDByGeo:
		anlyseSLDV6V4Geo() 					// 第四：分析SLD
	case constants.CCmdAnaSLDTimesByGeo:
		anlyseSLDTimesV6V4Geo()				// 分析SLD请求次数
	case constants.CCmdAll:
		anlyseTLD()							// 分析TLD
		anlyseDNSTimesV6V4Geo() 			// 第一：分析dns次数
		anlyseDomainV6V4Geo()   			// 第二：分析活跃域名
		anlyseIPv6V6V4Geo()     			// 第三：分析活跃IPv6
		anlyseSLDV6V4Geo()      			// 第四：分析SLD
		anlyseSLDTimesV6V4Geo()				// 分析SLD请求次数

	default:
		util.LogRecord("什么也没做\tPlease add the correct [-function parm]")
		goto End
	}

	End:
	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: ")
}

/*
	第一：合并V6V4地理
 */
func unionV6V4Geo() {
	if variables.DNSFileV6GeoV4GeoName == "" {
		variables.DNSFileV6GeoV4GeoName = GetTmpFileName(constants.DNSFileV6GeoV4GeoName, constants.DNSFileTempExtion)
		getV6V4Geo(variables.DNSFileUnionV4Name, variables.DNSFileV6GeoV4GeoName)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileV6GeoV4GeoName))
	}
}

/*
	分析DNS请求次数
 */
func anlyseDNSTimesV6V4Geo() {
	unionV6V4Geo()
	if variables.JsonV6DNSTimes == "" {
		variables.JsonV6DNSTimes = GetResFileName(constants.JsonV6DNSTimes + "-" + variables.DNSDateSpec, constants.JsonExtion)
		analyseDNSRequestTimesByGeo(variables.DNSFileV6GeoV4GeoName, variables.JsonV6DNSTimes)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.JsonV6DNSTimes))
	}
	if variables.DNSDateBefore != constants.DateExample {
		unonDNSTimesV6V4Geo()
	}
}

/*
	合并DNS请求次数
 */
func unonDNSTimesV6V4Geo() {
	if variables.JsonV6DNSTimes == "" {
		variables.JsonV6DNSTimes = GetResFileName(constants.JsonV6DNSTimes + "-" + variables.DNSDateSpec, constants.JsonExtion)
	}
	if variables.JsonV6DNSTimesBefore == "" {
		variables.JsonV6DNSTimesBefore = GetBeforeResFileName(constants.JsonV6DNSTimes + "-By" + variables.DNSDateBefore, constants.JsonExtion)
	}
	if variables.JsonV6DNSTimesTotal == "" {
		variables.JsonV6DNSTimesTotal = GetResFileName(constants.JsonV6DNSTimes + "-By" + variables.DNSDateSpec, constants.JsonExtion)
	}
	unionJsonResult(variables.JsonV6DNSTimesBefore, variables.JsonV6DNSTimes, variables.JsonV6DNSTimesTotal)
}

/*
	第二：去重域名
 */
func uniqDomainByV6V4Geo() {
	unionV6V4Geo()
	if variables.DNSFileGeoUniqDomain == "" {
		variables.DNSFileGeoUniqDomain = GetTmpFileName(constants.DNSFileGeoUniqDomain, constants.DNSFileTempExtion)
		uniqueDomainByGeo(variables.DNSFileV6GeoV4GeoName, variables.DNSFileGeoUniqDomain)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileGeoUniqDomain))
	}
}

/*
	分析活跃域名
 */
func anlyseDomainV6V4Geo() {
	uniqDomainByV6V4Geo()
	if variables.JsonV6DomainAlive == "" {
		variables.JsonV6DomainAlive = GetResFileName(constants.JsonV6DomainAlive+"-"+variables.DNSDateSpec, constants.JsonExtion)
		analyseAliveDomainByGeo(variables.DNSFileGeoUniqDomain, variables.JsonV6DomainAlive)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.JsonV6DomainAlive))
	}
	if variables.DNSDateBefore != constants.DateExample {
		unonDomainV6V4Geo()
	}
}

/*
	合并活跃域名
 */
func unonDomainV6V4Geo() {
	if variables.JsonV6DomainAlive == "" {
		variables.JsonV6DomainAlive = GetResFileName(constants.JsonV6DomainAlive + "-" + variables.DNSDateSpec, constants.JsonExtion)
	}
	if variables.JsonV6DomainAliveBefore == "" {
		variables.JsonV6DomainAliveBefore = GetBeforeResFileName(constants.JsonV6DomainAlive + "-By" + variables.DNSDateBefore, constants.JsonExtion)
	}
	if variables.JsonV6DomainAliveTotal == "" {
		variables.JsonV6DomainAliveTotal = GetResFileName(constants.JsonV6DomainAlive + "-By" + variables.DNSDateSpec, constants.JsonExtion)
	}
	unionJsonResult(variables.JsonV6DomainAliveBefore, variables.JsonV6DomainAlive, variables.JsonV6DomainAliveTotal)
}

/*
	第三：去重IPv6
 */
func uniqIPv6ByV6V4Geo() {
	unionV6V4Geo()
	if variables.DNSFileGeoUniqIPv6 == "" {
		variables.DNSFileGeoUniqIPv6 = GetTmpFileName(constants.DNSFileGeoUniqIPv6, constants.DNSFileTempExtion)
		uniqueIPv6ByGeo(variables.DNSFileV6GeoV4GeoName, variables.DNSFileGeoUniqIPv6)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileGeoUniqIPv6))
	}
}

/*
	分析活跃IPv6
 */
func anlyseIPv6V6V4Geo() {
	uniqIPv6ByV6V4Geo()
	if variables.JsonV6IPv6Alive == "" {
		variables.JsonV6IPv6Alive = GetResFileName(constants.JsonV6IPv6Alive+"-"+variables.DNSDateSpec, constants.JsonExtion)
		analyseAliveIPv6ByGeo(variables.DNSFileGeoUniqIPv6, variables.JsonV6IPv6Alive)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.JsonV6IPv6Alive))
	}
	if variables.DNSDateBefore != constants.DateExample {
		unonIPv6V6V4Geo()
	}
}

/*
	合并活跃IPv6
 */
func unonIPv6V6V4Geo() {
	if variables.JsonV6IPv6Alive == "" {
		variables.JsonV6IPv6Alive = GetResFileName(constants.JsonV6IPv6Alive + "-" + variables.DNSDateSpec, constants.JsonExtion)
	}
	if variables.JsonV6IPv6AliveBefore == "" {
		variables.JsonV6IPv6AliveBefore = GetBeforeResFileName(constants.JsonV6IPv6Alive + "-By" + variables.DNSDateBefore, constants.JsonExtion)
	}
	if variables.JsonV6IPv6AliveTotal == "" {
		variables.JsonV6IPv6AliveTotal = GetResFileName(constants.JsonV6IPv6Alive + "-By" + variables.DNSDateSpec, constants.JsonExtion)
	}
	unionJsonResult(variables.JsonV6IPv6AliveBefore, variables.JsonV6IPv6Alive, variables.JsonV6IPv6AliveTotal)
}

/*
	第四：去重SLD
 */
func uniqSLDByV6V4Geo() {
	unionV6V4Geo()
	if variables.DNSFileV6GeoUniqSLD == "" || variables.DNSFileV4GeoUniqSLD == "" {
		variables.DNSFileV6GeoUniqSLD = GetTmpFileName(constants.DNSFileV6GeoUniqSLD, constants.DNSFileTempExtion)
		variables.DNSFileV4GeoUniqSLD = GetTmpFileName(constants.DNSFileV4GeoUniqSLD, constants.DNSFileTempExtion)
		uniqueSLDByGeo(variables.DNSFileV6GeoV4GeoName, variables.DNSFileV6GeoUniqSLD, variables.DNSFileV4GeoUniqSLD)
	} else {
		util.LogRecord(fmt.Sprintf("%s && %s existed", variables.DNSFileV6GeoUniqSLD, variables.DNSFileV4GeoUniqSLD))
	}
}

/*
	分析SLD
 */
func anlyseSLDV6V4Geo() {
	uniqSLDByV6V4Geo()
	if variables.JsonV6SLDAlive == "" {
		variables.JsonV6SLDAlive = GetResFileName(constants.JsonV6SLDAlive+"-"+variables.DNSDateSpec, constants.JsonExtion)
		analyseAliveSLDByGeo(variables.DNSFileV6GeoUniqSLD, variables.DNSFileV4GeoUniqSLD, variables.JsonV6SLDAlive)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.JsonV6SLDAlive))
	}
	if variables.DNSDateBefore != constants.DateExample {
		unonSLDV6V4Geo()
	}
}

/*
	合并活跃SLD
 */
func unonSLDV6V4Geo() {
	if variables.JsonV6SLDAlive == "" {
		variables.JsonV6SLDAlive = GetResFileName(constants.JsonV6SLDAlive + "-" + variables.DNSDateSpec, constants.JsonExtion)
	}
	if variables.JsonV6SLDAliveBefore == "" {
		variables.JsonV6SLDAliveBefore = GetBeforeResFileName(constants.JsonV6SLDAlive + "-By" + variables.DNSDateBefore, constants.JsonExtion)
	}
	if variables.JsonV6SLDAliveTotal == "" {
		variables.JsonV6SLDAliveTotal = GetResFileName(constants.JsonV6SLDAlive + "-By" + variables.DNSDateSpec, constants.JsonExtion)
	}
	unionJsonResult(variables.JsonV6SLDAliveBefore, variables.JsonV6SLDAlive, variables.JsonV6SLDAliveTotal)
}

/*
	分析SLD请求次数
 */
func anlyseSLDTimesV6V4Geo() {
	uniqSLDByV6V4Geo()
	if variables.JsonV6SLDTimes == "" {
		variables.JsonV6SLDTimes = GetResFileName(constants.JsonV6SLDTimes+"-"+variables.DNSDateSpec, constants.JsonExtion)
		analyseSLDRequestTimesByGeo(variables.DNSFileV6GeoUniqSLD, variables.DNSFileV4GeoUniqSLD, variables.JsonV6SLDTimes)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.JsonV6SLDTimes))
	}
}
//

//// 分析TLD
func analyseTLD(ccmd uint8) {
	timeNow := time.Now()
	util.LogRecord("Excuting: ")

	switch ccmd {
	case constants.CCmdUniqTLD:
		uniqTLD() 						// 去重TLD
	case constants.CCmdAnaTLDTimes:
		anlyseTLD() 					// 分析TLD
	default:
		util.LogRecord("什么也没做\tPlease add the correct [-function parm]")
		goto End
	}

	End:
	util.LogRecord(fmt.Sprintf("cost: %ds", time.Now().Sub(timeNow) / time.Second))
	util.LogRecord("Ending: ")
}
/*
	去重TLD
 */
func uniqTLD() {
	unionDNSFiles()
	if variables.DNSFileUniqTLD == "" {
		variables.DNSFileUniqTLD = GetTmpFileName(constants.DNSFileUniqTLD, constants.DNSFileTempExtion)
		uniqueTLD(variables.DNSFileUnionName, variables.DNSFileUniqTLD)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.DNSFileUniqTLD))
	}
}

/*
	分析TLD
 */
func anlyseTLD() {
	uniqTLD()
	if variables.JsonTLDTimes == "" {
		variables.JsonTLDTimes = GetResFileName(constants.JsonTLDTimes+"-"+variables.DNSDateSpec, constants.JsonExtion)
		analyseTLDRequestTimes(variables.DNSFileUniqTLD, variables.JsonTLDTimes)
	} else {
		util.LogRecord(fmt.Sprintf("%s existed", variables.JsonTLDTimes))
	}
}

////
/*
	根据MaxMind数据库查询IP地理
*/
func GetIPsGeoByMM(ips string, ipDir string) {
	if ips != "" {
		getGeo(ips)
	} else {
		util.LogRecord("什么也没做\tPlease add the correct [-i parm]")
	}
	if ipDir != "" {
		variables.IPGeoName = GetResFileName(time.Now().Format(fmt.Sprintf("%s-%s", constants.IPGeoName, constants.DateFormat)), constants.IPGeoExtion)
		getGeoByFile(ipDir, variables.IPGeoName)
	} else {
		util.LogRecord("什么也没做\tPlease add the correct [-id parm]")
	}
}
//

////
/*
	查询域名IP
 */
func LookUpIPByDomain(domains string, domainFile string) {
	if domains != "" {
		lookUpIP(domains)
	} else {
		util.LogRecord("什么也没做\tPlease add the correct [-dm parm]")
	}
	if domainFile != "" {
		variables.DomainIpName = GetResFileName(time.Now().Format(fmt.Sprintf("%s-%s", constants.DomainIpName, constants.DateFormat)), constants.DomainIpExtion)
		lookUpIPv4ByFileMulCH(domainFile, variables.DomainIpName)
	} else {
		util.LogRecord("什么也没做\tPlease add the correct [-dmd parm]")
	}
}

/*
	查询域名IP通过ZDNS
 */
func ZDNSLookUpIPByDomain(domains string, domainFile string) {
	if domains != "" {
		zdnslookUpIP(domains)
	} else {
		util.LogRecord("什么也没做\tPlease add the correct [-dm parm]")
	}
	if domainFile != "" {
		variables.DomainIpDetlName = GetResFileName(time.Now().Format(fmt.Sprintf("%s-%s", constants.DomainIpDetlName, constants.DateFormat)), constants.DomainIpExtion)
		zdnslookUpIPByFile(domainFile, variables.DomainIpDetlName)
		variables.DomainIpName = GetResFileName(time.Now().Format(fmt.Sprintf("%s-%s", constants.DomainIpName, constants.DateFormat)), constants.DomainIpExtion)
		getSimpleIPv4(variables.DomainIpDetlName, variables.DomainIpName)
	} else {
		util.LogRecord("什么也没做\tPlease add the correct [-dmd parm]")
	}
}
//

////
/*
	合并文件
 */
func UnionFiles(fileDir string) {
	if fileDir != "" {
		variables.UnionFileName = GetResFileName(time.Now().Format(fmt.Sprintf("%s-%s", constants.UnionFileName, constants.DateFormat)), constants.UnionFileExtion)
		UnionDNSFileOnDir(fileDir, variables.UnionFileName)
	} else {
		util.LogRecord("什么也没做\tPlease add the correct [-d parm]")
	}
}

func GetGeoPercentByFile(fileName string) {
	getGeoPercentByFile(fileName)
}
