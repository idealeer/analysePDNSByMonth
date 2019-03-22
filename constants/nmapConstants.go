/*
@File : nmapConstants.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-20 19:32
*/

package constants

const NmapSigLineStartHost		string = "Host: "		// 有效Nmap结果行前缀
const NmapSigResStartHost		string = "Ports: "		// 有效Nmap端口状态前缀

const (
	NmapSigHostIndex		= iota
	NmapSigPortIndex
)

// ip位置
const (
	NmapHostIndex			= iota
	NmapIPIndex
)

// 端口位置
const (
	NmapPortIndex			= iota
	NmapStatisIndex
	NmapTDIndex
	NmapAppIndex
)

const NmapIPGap			string = " "

const NmapPortGap			string = ", "
const NmapPSGap				string = "/"

const NmapIPv6File			string = "ipv6Nmap"
const NmapIPv4File			string = "ipv4Nmap"

const NmapIPv6PortFile		string = "ipv6Port"
const NmapIPv4PortFile		string = "ipv4Port"
const NmapHttpOpenFile		string = "httpOpenIpv6"

const NmapFileExtion		string = "txt"

const NmapHttpPort			string = "80"

// Nmap扫描结果
const (
	NmapResOpen				string = "open"
	NmapStatisOpenNoSig		string = "open-notSig"	// 开放但无效
)
