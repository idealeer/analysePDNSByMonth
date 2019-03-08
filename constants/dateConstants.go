/*
@File : dateConstants.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-13 10:41
*/

package constants

const DateFormat		string = "2006-01-02"				// 日期格式化字符串
const DateTimeFormat	string = "2006-01-02 15:04:05"		// 日期时间格式化字符串

const DateFormer		string = "1970-01-01 00:00:00"		// 较早的日期

const DateRegexp  		string = `[\d]{4}((0[1-9])|1[0-2])`	// 月份日期指定正则表达式
const DateExample		string = "197006"					// 月份日期示例

const YearBeforeStart	int = 2015
const MonthBeforeStart	int = 7
const YearBeforeEnd		int = 2018
const MonthBeforeEnd	int = 8

const ApiCountStartIndex	int = 18						// 每个国家的月份数据开始位置
