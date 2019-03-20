/*
@File : resType.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-18 17:34
*/

package types

type DCI struct {
	Domain   	string					`json:"domain,omitempty"`
	Count 		int64					`json:"count,omitempty"`
}

type DCIList []DCI // 单个国家域名+次数

func (p DCIList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p DCIList) Len() int           { return len(p) }
func (p DCIList) Less(i, j int) bool { return p[i].Count < p[j].Count }

type DCIListMap map[string]DCIList // SLD与TLD输出格式


type TPMSF64 map[string]float64     			// 自定义类型：map[string]float64
type TPMSTPMSF64 map[string]TPMSF64 			// 自定义类型：map[string](map[string]float64)

