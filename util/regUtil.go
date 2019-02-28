/*
@File : regUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-27 17:59
*/

package util

import "regexp"

func MatchRegexp(pattern string, s string) bool {
	if m, _ := regexp.MatchString(pattern, s); m {
		return true
	} else {
		return false
	}
}
