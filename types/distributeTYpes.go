/*
@File : distributeTYpes.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-03-20 15:40
*/

package types

type DisC struct {
	Distribution   	string							`json:"distribution,omitempty"`
	Count 			int64							`json:"count,omitempty"`
}

type DisCList []DisC

func (p DisCList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p DisCList) Len() int           { return len(p) }
func (p DisCList) Less(i, j int) bool { return p[i].Count < p[j].Count }
