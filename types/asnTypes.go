/*
@File : asnTypes.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-20 15:43
*/

package types

type ASNC struct {
	ASNNum			uint							`json:"asnNum,omitempty"`
	ASNName   		string							`json:"asnName,omitempty"`
	Count 			int64							`json:"count,omitempty"`
}

type ASNCList []ASNC

func (p ASNCList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p ASNCList) Len() int           { return len(p) }
func (p ASNCList) Less(i, j int) bool { return p[i].Count < p[j].Count }

type ASNT struct {
	ASNName			string
	Count			int64
}

type ASNTMap map[uint]ASNT		// map
