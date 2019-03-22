/*
@File : geoTypes.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-22 11:50
*/

package types

type LonLa struct {
	Longitute	float64
	Latitute	float64
}

type LonLaList	[]LonLa				// 数组

type LonLaSim		[2]float64
type LonLaSimList	[]LonLaSim		// 数组
