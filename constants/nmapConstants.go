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

const (
	NmapPortIndex			= iota
	NmapStatisIndex
	NmapTDIndex
	NmapAppIndex
)

const NmapPortGap			string = ", "
const NmapPSGap				string = "/"

const NmapIPv6File			string = "ipv6Nmap"
const NmapIPv4File			string = "ipv4Nmap"

const NmapIPv6PortFile		string = "ipv6Port"
const NmapIPv4PortFile		string = "ipv4Port"

const NmapFileExtion		string = "txt"
