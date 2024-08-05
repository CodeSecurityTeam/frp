package myutil

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/xx/xxx/pkg/msg"
)

func GetMessage(serverIp string, remoteIp string, loginMsg *msg.Login) string {
	msg := fmt.Sprintf(`客户端信息
remote ip: %v
local ip: %v
hostname: %v
os: %v
arch: %v
username: %v
version: %v`, remoteIp, loginMsg.Ip, loginMsg.Hostname, loginMsg.Os, loginMsg.Arch, loginMsg.UserName, loginMsg.Version)
	if loginMsg.SocksPort != 0 {
		msg += "\n\n"
		msg += fmt.Sprintf(`socks 代理信息
server ip: %v
port: %v`, serverIp, loginMsg.SocksPort)
		if loginMsg.SocksUser != "" && loginMsg.SocksPass != "" {
			msg += "\n"
			msg += fmt.Sprintf(`user: %v
pass: %v`, loginMsg.SocksUser, loginMsg.SocksPass)
		}
	}
	return msg
}

type MsgDingDing struct {
	Msgtype  string              `json:"msgtype"`
	Markdown MsgDingDingMarkdown `json:"markdown"`
	//Markdown struct {
	//	Title string `json:"title"`
	//	Text  string `json:"text"`
	//} `json:"markdown"`
}

type MsgDingDingMarkdown struct {
	Title string `json:"title"`
	Text  string `json:"text"`
}

func PostMsg(webhook, serverIp string, remoteIp string, loginMsg *msg.Login) {
	var msgStr string
	msgStr = fmt.Sprintf("### <font color=\"#3c78d8\"> 消息类型：FRP 上线通知</font>  \n\n    \n\n  **客户端信息**  \n\n  - remote ip：%s - local ip：%s  \n\n  - hostname：%s  \n\n  - os：%s  \n\n  - arch：%s  \n\n  - username：%s  \n\n  - version：%s  \n\n    \n\n  **Socks5代理信息**  \n\n  - **socks5://%s:%s@%s:%d**", remoteIp, loginMsg.Ip, loginMsg.Hostname, loginMsg.Os, loginMsg.Arch, loginMsg.UserName, loginMsg.Version, loginMsg.SocksUser, loginMsg.SocksPass, serverIp, loginMsg.SocksPort)
	url := webhook
	data := MsgDingDing{
		Msgtype: "markdown",
		Markdown: MsgDingDingMarkdown{
			Title: "消息类型：frp",
			Text:  msgStr,
		},
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("JSON序列化错误:", err)
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second, // 设置超时时间为30秒
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 忽略证书验证
		},
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("创建请求时发生错误:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = client.Do(req)
	if err != nil {
		fmt.Println("发送请求时发生错误:", err)
		return
	}
	//defer resp.Body.Close()
	//// 读取响应内容
	//body, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	fmt.Println("读取响应时发生错误:", err)
	//	return
	//}
	//// 打印响应内容
	//fmt.Println("响应内容:", string(body))
}

func PostMsgExit(webhook string, loginMsg *msg.Login) {
	var msgStr string
	msgStr = fmt.Sprintf("### <font color=\"#ff0000\">消息类型：FRP 掉线通知</font> \n\n **客户端信息** \n - local ip：%s \n - hostname：%s \n - os：%s \n - arch：%s \n - username：%s \n", loginMsg.Ip, loginMsg.Hostname, loginMsg.Os, loginMsg.Arch, loginMsg.UserName)
	url := webhook
	data := MsgDingDing{
		Msgtype: "markdown",
		Markdown: MsgDingDingMarkdown{
			Title: "消息类型：frp",
			Text:  msgStr,
		},
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("JSON序列化错误:", err)
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second, // 设置超时时间为30秒
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 忽略证书验证
		},
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("创建请求时发生错误:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	_, err = client.Do(req)
	if err != nil {
		fmt.Println("发送请求时发生错误:", err)
		return
	}
}
