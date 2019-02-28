/*
@File : logConstants.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-01-29 12:15
*/

package constants

const LogShow		bool = true				// 输出日志到控制台
const LogHide		bool = false			// 隐藏日志到控制台
const LogFile		bool = true				// 日志记录文件
const LogNoFile		bool = false			// 日志记录无文件

const (										// 日志等级
	LogLev1			int8 = iota
	LogLev2
	LogLev3
	LogLev4
	LogLev5

	LogLevMax
)

const LogSmlNum		uint64 = 1e+01			// 日志小间隔
const LogBigNum		uint64 = 1e+04			// 日志大间隔

const LogFileName	string = "PDNS分析日志"	// 日志文件名
const LogExtion		string = "log"			// 日志文件扩展名
