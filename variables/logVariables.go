/*
@File : logVariables.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 11:49
*/

package variables

import (
	"os"
)

var LogShow			bool		// 日志输出与否
var LogFile			bool		// 日志记录与否

var LogFileName 	string		// 日志文件名称
var LogWriter		*os.File	// 日志输出流

var LogShowLev		int8		// 日志等级，不可初始化
var LogShowBigLag	uint64
var LogShowSmlLag	uint64
