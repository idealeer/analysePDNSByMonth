/*
@File : excelUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-12 08:40
*/

package util

import "fmt"

/*
	获得Excel指定列名
 */
func GetExcelColName(num int) string {
	colName := ""
	for {
		if num <= 0 {
			break
		}
		numR := num % 26
		if numR == 0 {
			numR = 26
		}
		colName += fmt.Sprintf("%c", 'A' + numR - 1)
		if num == 26 {
			break
		}
		if num % 26 == 0 {
			num--
		}
		num /= 26
	}
	return ReverseString(colName)
}

/*
	获得Excel指定区间的列名
 */
func GetExcelColNameList(numStart int, numEnd int) []string {
	var cnl = make([]string, 0)
	for i := numStart; i <= numEnd; i++ {
		cnl = append(cnl, GetExcelColName(i))
	}
	return cnl
}
