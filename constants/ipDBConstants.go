/*
@File : ipDBConstants.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-01-29 11:28
*/

package constants

const MaxMind 			int8 = 0		// MaxMind数据库

// MaxMind数据库
const MMCNNameIndex		int8 = 0		// 中文名称位置
const MMENNameIndex 	int8 = 1		// 英文名称位置
const MMCodeIndex		int8 = 2		// ISO-Code位置
const MMIDIndex 		int8 = 3		// Name-ID位置

// iso、中文国家名文件
const (
	ISOIndex			int8 = iota
	CNNameIndex
)

const ASNNullNumber		uint = 0
const ASNNullString		string = "null"
