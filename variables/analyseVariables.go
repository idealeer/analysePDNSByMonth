/*
@File : analyseVariables.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-01-29 11:54
*/

package variables

//// 原始文件
var DNSFileDir					string				// dns文件文件夹
var DNSFileName					string				// 单个dns文件名
var ZDNSExeFileName				string				// ZDNS可执行文件

var ResBeforeDir				string				// 先前结果文件夹
var RecordHisDir				string				// 历史文件保存文件夹

var ApiResDir					string				// 历史api结果文件

var D4FileName 					string 				// 域名v4地址字典文件
var V6GeoFileName				string				// v6地理库
var V4GeoFileName				string				// v4地理库

var ResFileName					string				// 存储结果文件


//

//// 合并文件
var DNSFileUnionName			string				// 合并后的dns文件名
//

//// DNS查询V4地址文件
var DNSFileUniqDomain			string 				// 去重域名文件
var DNSFileUniqDomainIPv4Detl	string 				// 去重域名+V4详细地址文件
var DNSFileUniqDomainIPv4		string 				// 去重域名+V4地址文件
var DNSFileUnionV4Name 			string           	// 合并V4地址文件
//

//// TLD去重文件
var DNSFileUniqTLD				string				// 去重TLD文件
//

//// 地理分析临时文件
var DNSFileV6GeoV4GeoName		string				// V6地理+V4地理文件
var DNSFileGeoUniqDomain 		string				// 地理去重域名文件
var DNSFileGeoUniqIPv6 			string    			// 地理去重IPv6地址文件
var DNSFileV6GeoUniqSLD 		string      		// 地理去重SLD文件
var DNSFileV4GeoUniqSLD 		string      		// 地理去重SLD文件
//

//// 文件夹
var DNSFileTempDir				string				// 临时文件夹
var DNSFileResDir				string				// 结果文件夹
//

//// 结果文件
var IPGeoName					string				// ip地理文件
var IPASNName					string				// ipASN文件
var IPCityName					string				// ipCity文件
var IPLonLaName					string				// ip经纬度文件
var IPCNLonLaName				string				// ipCN经纬度文件


var DomainIpDetlName			string				// 域名IP详细文件
var DomainIpName				string				// 域名IP文件
var UnionFileName				string				// 合并文件名称
//

// TLD分析结果文件
var JsonTLDTimes				string				// IPv6 TLD请求次数

// V6+V4地理分析结果文件
var JsonV6DNSTimes 				string    			// "IPv6 DNS请求趋势"
var JsonV6DomainAlive 			string 				// "IPv6 域名活跃趋势"
var JsonV6IPv6Alive 			string   			// "IPv6 IPv6活跃趋势"
var JsonV6SLDAlive 				string    			// "IPv6 SLD活跃趋势"
var JsonV6SLDTimes				string				// "IPv6 SLD请求次数"
//

// V6+V4地理先前分析结果文件
var JsonV6DNSTimesBefore 		string    			// "IPv6 DNS请求趋势"
var JsonV6DomainAliveBefore 	string 				// "IPv6 域名活跃趋势"
var JsonV6IPv6AliveBefore 		string   			// "IPv6 IPv6活跃趋势"
var JsonV6SLDAliveBefore 		string    			// "IPv6 SLD活跃趋势"
//

// V6+V4地理分析结果总文件
var JsonV6DNSTimesTotal 		string    			// "IPv6 DNS请求趋势"
var JsonV6DomainAliveTotal 		string 				// "IPv6 域名活跃趋势"
var JsonV6IPv6AliveTotal 		string   			// "IPv6 IPv6活跃趋势"
var JsonV6SLDAliveTotal 		string    			// "IPv6 SLD活跃趋势"
//

// V6+V4地理分析结果api文件
var JsonV6DNSTimesApi 			string    			// "IPv6 DNS请求趋势"
var JsonV6DomainAliveApi 		string 				// "IPv6 域名活跃趋势"
var JsonV6IPv6AliveApi 			string   			// "IPv6 IPv6活跃趋势"
var JsonV6SLDAliveApi 			string    			// "IPv6 SLD活跃趋势"
//

// 数据显示条数
var TopNDomains					int64

//// 数据记录
var DomainIPMap 				map[string]string 	// 域名IP映射表
//
