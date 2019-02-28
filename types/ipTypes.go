/*
@File : ipTypes.go
@Author : ida
@Mail : idealeer521@gmail.com 
@Software: GoLand
@Time : 2019-02-24 15:58
*/

package types

type ALookUpResult struct {
	Name        string        	`json:"name,omitempty"`
	Nameserver  string        	`json:"nameserver,omitempty"`
	Class       string        	`json:"class,omitempty"`
	Status      string        	`json:"status,omitempty"`
	Timestamp   string        	`json:"timestamp,omitempty"`
	Data        IPv4Addr   		`json:"data,omitempty"`
}

type IPv4Addr struct {
	IPv4Addresses []string 		`json:"ipv4_addresses,omitempty"`
}
