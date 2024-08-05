// Copyright 2019 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"time"

	v1 "github.com/xx/xxx/pkg/config/v1"
)

var Socks5Port int

func init() {
	RegisterProxyFactory(reflect.TypeOf(&v1.TCPProxyConfig{}), NewTCPProxy)
	rand.Seed(time.Now().UnixNano())
}

type TCPProxy struct {
	*BaseProxy
	cfg *v1.TCPProxyConfig

	realBindPort int
}

func NewTCPProxy(baseProxy *BaseProxy) Proxy {
	unwrapped, ok := baseProxy.GetConfigurer().(*v1.TCPProxyConfig)
	if !ok {
		return nil
	}
	baseProxy.usedPortsNum = 1
	return &TCPProxy{
		BaseProxy: baseProxy,
		cfg:       unwrapped,
	}
}

// isPortAvailable 检查指定端口是否被占用
func isPortAvailable(port int) bool {
	// 尝试监听本地地址的指定端口
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		// 如果发生错误，则端口可能已被占用
		return false
	}
	// 关闭监听器，因为我们只是检查端口状态
	ln.Close()
	// 如果没有错误，端口是可用的
	return true
}

// findAvailablePort 在指定范围内找到一个未被占用的端口
func findAvailablePort(min, max int) (int, error) {
	if max < min {
		return 0, fmt.Errorf("invalid port range: %d - %d", min, max)
	}

	for {
		port := rand.Intn(max-min+1) + min // 生成[min, max]范围内的随机端口
		if isPortAvailable(port) {
			return port, nil
		}
	}
}

func (pxy *TCPProxy) Run() (remoteAddr string, err error) {
	// 随机获取一个可用端口
	portInt, err := findAvailablePort(40000, 50000)
	if err != nil {
		return
	}
	pxy.cfg.RemotePort = portInt
	Socks5Port = portInt

	xl := pxy.xl
	if pxy.cfg.LoadBalancer.Group != "" {
		l, realBindPort, errRet := pxy.rc.TCPGroupCtl.Listen(pxy.name, pxy.cfg.LoadBalancer.Group, pxy.cfg.LoadBalancer.GroupKey,
			pxy.serverCfg.ProxyBindAddr, pxy.cfg.RemotePort)
		if errRet != nil {
			err = errRet
			return
		}
		defer func() {
			if err != nil {
				l.Close()
			}
		}()
		pxy.realBindPort = realBindPort
		pxy.listeners = append(pxy.listeners, l)
		xl.Infof("tcp proxy listen port [%d] in group [%s]", pxy.cfg.RemotePort, pxy.cfg.LoadBalancer.Group)
	} else {
		pxy.realBindPort, err = pxy.rc.TCPPortManager.Acquire(pxy.name, pxy.cfg.RemotePort)
		if err != nil {
			return
		}
		defer func() {
			if err != nil {
				pxy.rc.TCPPortManager.Release(pxy.realBindPort)
			}
		}()
		listener, errRet := net.Listen("tcp", net.JoinHostPort(pxy.serverCfg.ProxyBindAddr, strconv.Itoa(pxy.realBindPort)))
		if errRet != nil {
			err = errRet
			return
		}
		pxy.listeners = append(pxy.listeners, listener)
		xl.Infof("tcp proxy listen port [%d]", pxy.cfg.RemotePort)
	}

	pxy.cfg.RemotePort = pxy.realBindPort
	remoteAddr = fmt.Sprintf(":%d", pxy.realBindPort)
	pxy.startCommonTCPListenersHandler()
	return
}

func (pxy *TCPProxy) Close() {
	pxy.BaseProxy.Close()
	if pxy.cfg.LoadBalancer.Group == "" {
		pxy.rc.TCPPortManager.Release(pxy.realBindPort)
	}
}
