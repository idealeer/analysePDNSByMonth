/*
@File : ipDBVariables.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 09:11
*/

package variables

import "github.com/oschwald/geoip2-golang"

var MaxMindDBName	string			// MaxMindGeo数据库名称
var MaxMindReader	*geoip2.Reader	// MaxMindGeo数据库读取器

var MaxMindASNDBName	string			// MaxMindASN数据库名称
var MaxMindASNReader	*geoip2.Reader	// MaxMindASN数据库读取器

var MaxMindCityDBName	string			// MaxMindCity数据库名称
var MaxMindCityReader	*geoip2.Reader	// MaxMindCity数据库读取器
