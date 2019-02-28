/*
@File : numUtil.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-11 17:24
*/

package util

/*
	计算a的n次方
 */
func Pow(x uint64, n int8) uint64 {
	var ret uint64 = 1
	for n != 0 {
		if n % 2 != 0 {
			ret = ret * x
		}
		n /= 2
		x = x * x
	}
	return ret
}
