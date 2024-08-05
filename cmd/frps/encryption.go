package main

import (
	"encoding/base64"
	"fmt"
	"github.com/xx/xxx/pkg/util/myutil"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(encrypt)
}

var encrypt = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt frpc.toml",
	RunE: func(cmd *cobra.Command, args []string) error {
		if frpcFile == "" {
			fmt.Println("frpc.toml: the configuration file is not specified")
			return nil
		}
		if ossUrl == "" || ossDomain == "" {
			fmt.Println("Incomplete parameters: ossUrl or ossDomain")
			return nil
		}
		content, err := os.ReadFile(frpcFile)
		if err != nil {
			log.Fatal(err)
		}
		frpcDataStr := string(content)
		key := myutil.GenerateAESKey()
		encrypted := myutil.AesEncryptECB([]byte(frpcDataStr), []byte(key))
		encryptedB64 := base64.StdEncoding.EncodeToString(encrypted)
		outStr := fmt.Sprintf("%s", encryptedB64)
		if err := os.WriteFile("frpc_encrypt.txt", []byte(outStr), 0666); err != nil {
			log.Fatal(err)
		}

		key1 := []byte(myutil.GenerateAESKey()) // 加密的密钥
		url1 := base64.StdEncoding.EncodeToString(myutil.AesEncryptECB([]byte(ossUrl), key1))
		domain := base64.StdEncoding.EncodeToString(myutil.AesEncryptECB([]byte(ossDomain), key1))
		key2 := base64.StdEncoding.EncodeToString(myutil.AesEncryptECB([]byte(key), key1))
		bodyStr, err := ReadFile("../cmd1/frpc/main.txt")
		if err != nil {
			log.Fatal(err)
			return nil
		}
		bodyStr = strings.Replace(bodyStr, "{key}", key2, 1)
		bodyStr = strings.Replace(bodyStr, "{url}", url1, 1)
		bodyStr = strings.Replace(bodyStr, "{domain}", domain, 1)
		bodyStr = strings.Replace(bodyStr, "{key1}", string(key1), 1)
		err = ioutil.WriteFile("../cmd1/frpc/main.go", []byte(bodyStr), 0644)
		if err != nil {
			log.Fatal(err)
			return nil
		}
		log.Printf("[+] The frpc configuration file is encrypted successfully, please check the frpc_encrypt.txt file")
		return nil
	},
}

func ReadFile(filePath string) (string, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
