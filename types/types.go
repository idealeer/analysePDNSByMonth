/*
@File : types.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-01-29 11:37
*/

package types

type CC struct {
	Count	int64	// 次数
	Country	string	// 国家
}

type TPMSCC map[string]CC					// 自定义类型：map[string]CC

type TPMSS map[string]string				// 自定义类型：map[string]string
type TPMSTPMSS map[string]TPMSS				// 自定义类型：map[string](map[string]string)

type TPMSI64 map[string]int64     			// 自定义类型：map[string]int64
type TPMSTPMSI64 map[string]TPMSI64 		// 自定义类型：map[string](map[string]int64)
type TPMSTPMSTPMSI64 map[string]TPMSTPMSI64	// 自定义类型：map[string](map[string](map[string]int64))

type TC struct {
	TLD   string							`json:"tld,omitempty"`
	Count int64								`json:"count,omitempty"`
}

type TCList []TC

func (p TCList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p TCList) Len() int           { return len(p) }
func (p TCList) Less(i, j int) bool { return p[i].Count < p[j].Count }

type SC struct {
	SLD   string							`json:"sld,omitempty"`
	Count int64								`json:"count,omitempty"`
}

type SCList []SC

func (p SCList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p SCList) Len() int           { return len(p) }
func (p SCList) Less(i, j int) bool { return p[i].Count < p[j].Count }

type CMC struct {
	Country string  `json:"area,omitempty"`
	Counts  []int64 `json:"seens,omitempty"`
	Total   int64	`json:"total,omitempty"`
	rank	int32	`json:"rank,omitempty"`
}

type CMCList struct {
	Code	int32							`json:"code,omitempty"`
	Success	bool							`json:"success,omitempty"`
	Data	[]CMC							`json:"data,omitempty"`
}
