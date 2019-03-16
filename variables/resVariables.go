/*
@File : resVariables.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-15 18:36
*/

package variables

//// 结果输入信息

var	CPLNum		int64		// 中国人口总量
var CNZNum		int64		// 中国网民总量

var Countrys	string		// 分析的国家列表，逗号分隔

// 使用date中的变量
//var StartMonth	string			// 起始月份
//var EndMonth		string			// 截止月份

//

//// 自动生成
var TotalMonthNum	int64			// 月份总数
var TotalDayNum		int64			// 日份总数

//
var IsoCNNameFile	string			// 文件
var IsoCNNameMap	map[string]string	// 简称对应中文国家名
