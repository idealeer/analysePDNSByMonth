/*
@File : endMethods.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 14:39
*/

package analyse

import "analysePDNSByMonth/variables"

/*
	日志记录收尾
 */
func EndLog() {
	if variables.LogWriter != nil {
		variables.LogWriter.Close()
	}
}

/*
	MaxMind收尾
 */
func EndMaxMind() {
	if variables.MaxMindReader != nil {
		variables.MaxMindReader.Close()
	}
}