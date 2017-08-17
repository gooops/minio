package cmd

import (
	"fmt"

	"github.com/spf13/viper"
)

func init() {
	viper.AddConfigPath("./conf")
	viper.SetConfigName("tenants")
	viper.SetConfigType("json")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}
}

// GetCredentials get current tenant credentials.
func GetCredential_lp(accessKey string) credential {
	cred := credential{
		AccessKey: accessKey,
		SecretKey: viper.GetString(accessKey),
	}
	return cred
}

// func main(){
// 	fmt.Println("aaa")
// 	fmt.Println(viper.AllSettings())
// }
