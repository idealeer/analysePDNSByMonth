/*
@File : resConstants.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-15 18:56
*/

package constants

// dns请求次数
const ResStrDNSTimes		string = `DNS解析请求总次数达%d亿余次，平均每天%d万余次、每月%d万余次。单月请求次数，最多为%s的%d万余次，最少为%s的%d万余次。中国总人口近%d亿，这意味着平均每%d个国人每天对%sIPv6域名进行一次解析请求。截止2018年6月30日，中国网民达%d亿人，表明平均每%d位中国网民每天对%sIPv6域名进行一次解析请求。`

// IPv6活跃总量
const ResStrIPv6Alive		string = `IPv6地址活跃总量达%d万余个，平均每月活跃量为%d万余个。单月活跃量，最多为%s的%d万余个，最少为%s的%d个。`

// 域名活跃总量
const ResStrDomainAlive		string = `域名活跃总量达%d万个，平均每月活跃量为%d万余个。单月活跃量，最多为%s的%d万余个，最少为%s的%d个。`

// SLD活跃总量
const ResStrSLDAlive		string = `SLD活跃总量达%d万个，平均每月份活跃量为%d个。单月活跃量，最多为%s的%d个，最少为%s的%d个。`

// SLD请求次数
const ResStrSLDTimes		string = `在%s，Top50的SLD的请求总次数达%d亿余次，平均每天%d亿余次，最多的为访问“%s”的%d亿余次，访问排名50的“%s”也有%d万余次。`

// TLD请求次数
const ResStrTLDTimes		string = `在%s，Top50的TLD的请求次数达%d亿余次，平均每天%d亿余次，最多的为访问“%s”的%d亿余次，访问排名50的“%s”也有%d万余次。`

// IPv6地址、域名数量
const ResStrIPv6Times		string = `IPv6地址总数量达%d万，其中，`
const ResStrDomainTimes		string = `域名总数量达%d万，其中，`
const ResStrCTimes			string = `位于%s的有%d万，`

const ResFileName			string = "PDNS分析结果"

//// 展示结果

const IPv6TrendFolderName	string = "ipv6trend" 		// 结果文件夹
const ShowV4FolderName 		string = "v4"              	// v4结果文件夹
const ShowV6FolderName 		string = "v6"              	// v6结果文件夹

const ShowFileExtion		string = "txt"								// 文件后缀

const ShowDomainFName		string = "active_domain_by_area"			// 活跃域名
const ShowIPv6FName			string = "active_ipv6_by_area"				// 活跃IPv6
const ShowSLDFName			string = "active_sld_by_area"				// 活跃SLD
const ShowDNSTimes			string = "seen_by_country"					// DNS请求次数

const TopNSLD				string = "top_50_sld_by_area"				// topN-SLD
const TopNSLDTotal			string = "top_sld_seen"						// topN-SLD-Total
const TopNTLD				string = "top_tld_seen"						// topN-TLD

const ShowDomainDIPFName		string = "domain_divide_ip_by_area"			// 活跃域名量/活跃IP量
const ShowIPv6DSLDFName			string = "ip_divide_sld_by_area"			// 活跃IP量/活跃SLD量
const ShowDNSDDomainFName		string = "dns_divide_domain_by_area"		// DNS请求次数/活跃域名量
const ShowDNSDIPv6FName			string = "dns_divide_ip_by_area"			// DNS请求次数/活跃IP量
