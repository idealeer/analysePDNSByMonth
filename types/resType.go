/*
@File : resType.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-18 17:34
*/

package types

type DC struct {
	Domain   	string					`json:"domain,omitempty"`
	Count 		int64					`json:"count,omitempty"`
}

type DCList []DC						// 单个国家域名+次数

func (p DCList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p DCList) Len() int           { return len(p) }
func (p DCList) Less(i, j int) bool { return p[i].Count < p[j].Count }


type DCListMap	map[string]DCList		// SLD与TLD输出格式
