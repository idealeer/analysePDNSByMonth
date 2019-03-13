/*
@File : stringUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 08:39
*/

package util

import (
	"analysePDNSByMonth/constants"
	"bytes"
	"fmt"
	"strings"
)

/*
	字符串翻转
 */
func ReverseString(str string) string {
	var result string
	strLen := len(str)
	for i := 0; i < strLen; i++ {
		result = result + fmt.Sprintf("%c", str[strLen-i-1])
	}
	return result
}

/*
	获取有用的DNS-Count字段值
 */
func GetSignifcantCountData(data string) string {
	return strings.Split(data, ":")[constants.DataIndex]
}

/*
	获取有用的DNS-Domain字段值
 */
func GetSignifcantDomainData(data string) string {
	reverseDomain := strings.Split(strings.Split(data, ":")[constants.DataIndex], "+")[constants.DomainIndex]
	reverseDomainList := strings.Split(reverseDomain, ".")
	length := len(reverseDomainList)
	domain := reverseDomainList[length - 1]

	var resDomain bytes.Buffer
	resDomain.WriteString(domain)

	for i := length - 2; i >= 0; i-- {
		resDomain.WriteByte('.')
		resDomain.WriteString(reverseDomainList[i])
	}
	return resDomain.String()
}

/*
	获取有用的DNS-IPv6字段值
 */
func GetSignifcantIPv6Data(data string) string {
	return strings.Split(data, "data:")[constants.DataIndex]
}