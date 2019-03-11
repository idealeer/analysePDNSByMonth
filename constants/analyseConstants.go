/*
@File : analyseConstants.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 13:33
*/

package constants

//// 合并文件
const DNSFileUnionName			string = "pdnsUnion"							// 合并后的dns文件名
//

//// DNS查询V4地址文件
const DNSFileUniqDomain			string = "uniqDomain"           				// 去重域名文件
const DNSFileUniqDomainIPv4Detl	string = "uniqDomainIPv4Detail" 				// 去重域名+V4详细地址文件
const DNSFileUniqDomainIPv4		string = "uniqDomainIPv4"       				// 去重域名+V4地址文件
const DNSFileUnionV4Name 		string = "pdnsV4"                         		// 合并V4地址文件
//

//// TLD去重文件
const DNSFileUniqTLD 			string = "uniqTLD" 								// 去重TLD文件
//

//// 地理分析临时文件
const DNSFileV6GeoV4GeoName		string = "GeoPDNS"      						// V6地理+V4地理文件
const DNSFileGeoUniqDomain 		string = "GeoUniqDomain" 						// 地理去重域名文件
const DNSFileGeoUniqIPv6 		string = "GeoUniqIPv6"     						// 地理去重IPv6地址文件
const DNSFileV6GeoUniqSLD 		string = "GeoV6UniqSLD"            				// 地理去重SLD文件
const DNSFileV4GeoUniqSLD 		string = "GeoV4UniqSLD"            				// 地理去重SLD文件
//

//// 记录文件各字段位置
const RecordStartIndex			int8 = 0										// 字段起始位置
const DataIndex					int = 0											// 每个字段数据的有效位置
const DomainIndex				int = 0											// 域名的有效位置
// 原始记录文件
const (
	ODomainIndex				int8 = iota	+ RecordStartIndex					// 域名位置
	OCountIndex																	// 次数位置
	OIPv6Index																	// IPv6位置
)
//

// 合并后文件
const (
	UNDomainIndex				int8 = iota										// 域名位置
	UNCountIndex																// 次数位置
	UNIPv6Index																	// IPv6位置
)
//

// 去重TLD文件
const (
	UTTLDIndex					int8 = iota										// TLD位置
	UTCountIndex																// 次数位置
)

// 去重域名+IPv4文件
const (
	UDomainIndex				int8 = iota										// 去重域名位置
	UIPv4Index																	// 去重IPv4位置
)
//

// 合并V4地址文件
const (
	DV4DomainIndex				int8 = iota										// 域名位置
	DV4CountIndex																// 次数位置
	DV4IPv6Index																// IPv6位置
	DV4IPv4Index																// IPv4位置
)
//

// 合并V6地理+V4地理文件
const (
	GeoDomainIndex  				int8 = iota 								// 域名位置
	GeoCountIndex             													// 次数位置
	GeoIPv6Index              													// IPv6位置
	GeoIPv4Index               													// IPv4位置
	GeoV6GIndex                													// V6地理位置
	GeoV4GIndex                													// V4地理位置
)
//

// 去重域名文件+地理
const (
	GeoUDDomainIndex  			int8 = iota 									// 域名位置
	GeoUDV6GIndex                 												// V6地理位置
	GeoUDV4GIndex                 												// V4地理位置
)
//

// 去重IPv6文件+地理
const (
	GeoUIV6Index      			int8 = iota 									// 域名位置
	GeoUIV6GIndex                 												// V6地理位置
	GeoUIV4GIndex                 												// V4地理位置
)
//

// 去重SLD文件+V6地理
const (
	V6GeoUSSLDIndex     			int8 = iota 								// 域名位置
	V6GeoUSCountIndex               											// 次数位置
	V6GeoUSV6GIndex                 											// V6地理位置
)
//

// 去重SLD文件+V4地理
const (
	V4GeoUSSLDIndex     			int8 = iota 								// 域名位置
	V4GeoUSCountIndex               											// 次数位置
	V4GeoUSV4GIndex                 											// V4地理位置
)
//

//// 临时文件
const DNSFileTempExtion			string = "pdns"									// dns分析文件临时扩展名
const DNSTempFolder				string = "temp"									// dns临时文件夹
//

//// 结果文件
const DNSResFolder				string = "result"								// dns结果文件夹

// 域名IP结果文件
const DomainIpDetlName			string = "DomainIPDetail"						// 域名IP详细文件
const DomainIpName				string = "DomainIP"								// 域名IP文件
const DomainIpExtion			string = "di"									// 域名IP文件扩展名

// IP地理结果文件
const IPGeoName 				string = "IPGeo"            	   				// IP地理文件
const IPGeoExtion				string = "ig" 									// IP地理文件扩展名

// 合并文件结果文件
const UnionFileName				string = "UnionFile"							// 合并文件名称
const UnionFileExtion			string = "uf"									// 合并文件扩展名

//

//// 字符串
const TotalTimesString 			string = "total" 								// 统计"总数" 名
const V4GeoString 				string = "v4Geo"                 				// v4地理
const V6GeoString 				string = "v6Geo"                 				// v6地理

// 分析结果文件后缀
const JsonExtion  				string = "json"

// TLD分析结果文件
const JsonTLDTimes				string = "IPv6-TLD请求次数"						// IPv6 TLD请求次数

// 地理分析结果文件
const JsonV6DNSTimes 			string = "IPv6-DNS请求趋势"   					// "IPv6 DNS请求趋势"
const JsonV6DomainAlive 		string = "IPv6-域名活跃趋势" 						// "IPv6 域名活跃趋势"
const JsonV6IPv6Alive 			string = "IPv6-IP活跃趋势"   						// "IPv6 IPv6活跃趋势"
const JsonV6SLDAlive 			string = "IPv6-SLD活跃趋势"   					// "IPv6 SLD活跃趋势"
const JsonV6SLDTimes			string = "IPv6-SLD请求次数"						// "IPv6 SLD请求次数"
//

// 历史API文件后缀
const ApiExtion					string = "txt"

//// 命令参数
/// 一级命令
const (
	CmdAnalyse					uint8 = iota									// 分析命令
	CmdMMDB																		// IP数据库查询
	CmdUnionFile																// 合并文件
	CmdNS																		// 域名解析

	CmdTest
	CmdApi2Json																	// api结果转json

	CmdAnalyseMul																// 分析多个相邻月份

	CmdDefault
)
//

/// 二级命令
const (
	CCmdAll uint8 = iota 	// 执行全部分析

	CCmdUnionDNS    		// 合并dns记录
	CCmdUniqDomain  		// 去重域名
	CCmdNSIPv4      		// 查询IPv4地址
	CCmdUnionDNSV4  		// 合并V4地址

	CCmdUniqTLD				// 去重TLD
	CCmdAnaTLDTimes			// 统计TLD次数

	CCmdGetGeo            // 获取地理
	CCmdUniqDomainByGeo   // 去重域名By地理
	CCmdUniqIPv6ByGeo     // 去重IPv6By地址地理
	CCmdUniqSLDByGeo      // 去重SLDBy地理
	CCmdAnaDNSTimesByGeo  // 分析DNS请求次数By地理
	CCmdAnaDomainByGeo    // 分析域名By地理
	CCmdAnaIPv6ByGeo      // 分析IPv6地址By地理
	CCmdAnaSLDByGeo       // 分析SLDBy地理
	CCmdAnaSLDTimesByGeo  // 分析SLD请求次数By地理

	CCmdUnionBeforeRes		// 合并历史结果

	CCmdDefault
)

//
