package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jpillora/ipfilter"
	"github.com/ory-am/ladon"
	"github.com/spf13/viper"
)

type CIDRCondition struct {
	CIDRs string `json:"cidrs"`
}

func (c *CIDRCondition) GetName() string {
	return "IPCondition"
}

func (c *CIDRCondition) Fulfills(value interface{}, r *ladon.Request) bool {
	ips, ok := value.(string)
	if !ok {
		return false
	}

	filter, err := ipfilter.New(ipfilter.Options{
		AllowedIPs:     strings.Split(c.CIDRs, ","),
		BlockByDefault: true,
	})
	if err != nil {
		fmt.Println(err)
		return false
	}

	cips := strings.Split(ips, ",")
	for _, ip := range cips {
		if !filter.Allowed(ip) {
			if js, err := json.Marshal(r); err == nil {
				fmt.Printf("%v IP %s Access Deny!\n", string(js), ip)
			}
			return false
		}
	}
	return true
}

var (
	warden *ladon.Ladon
)

// 初始化
func init() {
	// 初始化 CIDRCondition
	ladon.ConditionFactories[new(CIDRCondition).GetName()] = func() ladon.Condition {
		return new(CIDRCondition)
	}

	// 加载策略文件
	viper.AddConfigPath("./conf")
	viper.SetConfigName("ladon")
	viper.SetConfigType("json")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	// 初始化策略
	warden = &ladon.Ladon{
		Manager: ladon.NewMemoryManager(),
	}

	for pk, pv := range viper.AllSettings() {
		var buf bytes.Buffer
		fmt.Println("初始化策略：", pk)
		enc := json.NewEncoder(&buf)
		enc.Encode(pv)

		pol := &ladon.DefaultPolicy{}
		err := json.Unmarshal(buf.Bytes(), pol)
		if err != nil {
			panic(err)
		}
		fmt.Println(pol)
		err = warden.Manager.Create(pol)
		if err != nil {
			panic(err)
		}
	}
}

func isAllowd(req *ladon.Request) error {
	return warden.IsAllowed(req)
}

// func main() {
//     // 拼装请求
//     req := &ladon.Request{
//         Subject:  "peter",
//         Action:   "delete",
//         Resource: "myrn:some.domain.com:resource:123",
//         Context: ladon.Context{
//             "owner":  "peter",
//             "cidr": "127.0.0.1,127.0.0.1,10.0.0.42,10.0.0.43",
//         },
//     }
//     // 验证权限
//     fmt.Println(warden.IsAllowed(req))
//     var a = ipfilter.Options{}
//     _ = a
// }
