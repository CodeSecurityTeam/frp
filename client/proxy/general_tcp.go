// Copyright 2023 The frp Authors
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
	"reflect"

	v1 "github.com/xx/xxx/pkg/config/v1"
)

func init() {
	pxyConfs := []v1.ProxyConfigurer{
		&v1.TCPProxyConfig{},
		&v1.HTTPProxyConfig{},
		&v1.HTTPSProxyConfig{},
		&v1.STCPProxyConfig{},
		&v1.TCPMuxProxyConfig{},
	}
	for _, cfg := range pxyConfs {
		RegisterProxyFactory(reflect.TypeOf(cfg), NewGeneralTCPProxy)
	}
}

// GeneralTCPProxy 是针对TCP协议的Proxy接口的通用实现。
// 如果默认的GeneralTCPProxy不能满足要求，可以自定义
// Proxy接口的实现。
type GeneralTCPProxy struct {
	*BaseProxy
}

func NewGeneralTCPProxy(baseProxy *BaseProxy, _ v1.ProxyConfigurer) Proxy {
	return &GeneralTCPProxy{
		BaseProxy: baseProxy,
	}
}
