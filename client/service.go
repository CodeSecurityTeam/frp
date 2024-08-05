// Copyright 2017 fatedier, fatedier@gmail.com
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

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/golib/crypto"
	"github.com/samber/lo"

	"github.com/xx/xxx/client/proxy"
	"github.com/xx/xxx/pkg/auth"
	v1 "github.com/xx/xxx/pkg/config/v1"
	"github.com/xx/xxx/pkg/msg"
	httppkg "github.com/xx/xxx/pkg/util/http"
	"github.com/xx/xxx/pkg/util/log"
	netpkg "github.com/xx/xxx/pkg/util/net"
	"github.com/xx/xxx/pkg/util/version"
	"github.com/xx/xxx/pkg/util/wait"
	"github.com/xx/xxx/pkg/util/xlog"
)

func init() {
	crypto.DefaultSalt = "frp"
	// 禁用 quic-go 的接收缓冲区警告。
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	// 默认禁用 quic-go 的 ECN 支持。这可能会导致某些操作系统出现问题。
	if os.Getenv("QUIC_GO_DISABLE_ECN") == "" {
		os.Setenv("QUIC_GO_DISABLE_ECN", "true")
	}
}

type cancelErr struct {
	Err error
}

func (e cancelErr) Error() string {
	return e.Err.Error()
}

// ServiceOptions 包含创建新客户服务的选项
type ServiceOptions struct {
	Common      *v1.ClientCommonConfig
	ProxyCfgs   []v1.ProxyConfigurer
	VisitorCfgs []v1.VisitorConfigurer

	// ConfigFilePath是用于初始化的配置文件的路径。
	// 如果为空，则表示不使用该配置文件进行初始化。
	// 可以使用命令行参数进行初始化，也可以直接调用。
	ConfigFilePath string

	// ClientSpec 是控制客户端行为的客户端规范
	ClientSpec *msg.ClientSpec

	// ConnectorCreator 是一个创建新的连接器以连接到服务器的函数。
	// Connector 屏蔽了底层的连接细节，无论是通过 TCP 还是 QUIC 连接，
	// 也不管是否使用多路复用。
	// 如果不设置，则使用默认的 frpc 连接器。
	// 通过使用自定义的 Connector，可以用来实现 VirtualClient，通过管道而不是真实的物理连接连接到 frps。
	ConnectorCreator func(context.Context, *v1.ClientCommonConfig) Connector

	// HandleWorkConnCb 是一个在创建新的工作连接时调用的回调函数
	//
	// 如果没有设置，则使用默认的frpc实现
	HandleWorkConnCb func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool
}

// setServiceOptionsDefault 设置服务选项默认值
func setServiceOptionsDefault(options *ServiceOptions) {
	if options.Common != nil {
		options.Common.Complete()
	}
	if options.ConnectorCreator == nil {
		options.ConnectorCreator = NewConnector
	}
}

// Service 是连接frps并提供代理服务的客户端服务
type Service struct {
	ctlMu sync.RWMutex
	// 管理器控制与服务器的连接
	ctl *Control
	// Uniq 从 frps 获取的 id，它将附加到 loginMsg。
	runID string

	// 根据所选方法设置身份验证
	authSetter auth.Setter

	// 管理 UI 和 API 的 Web 服务器
	webServer *httppkg.Server

	cfgMu       sync.RWMutex
	common      *v1.ClientCommonConfig
	proxyCfgs   []v1.ProxyConfigurer
	visitorCfgs []v1.VisitorConfigurer
	clientSpec  *msg.ClientSpec

	// 用于初始化此客户端的配置文件，如果未使用配置文件，则为空 字符串。
	configFilePath string

	// service context
	ctx context.Context
	// 致电取消以停止服务
	cancel                   context.CancelCauseFunc
	gracefulShutdownDuration time.Duration

	connectorCreator func(context.Context, *v1.ClientCommonConfig) Connector
	handleWorkConnCb func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool
}

func NewService(options ServiceOptions) (*Service, error) {
	setServiceOptionsDefault(&options)

	var webServer *httppkg.Server
	if options.Common.WebServer.Port > 0 {
		ws, err := httppkg.NewServer(options.Common.WebServer)
		if err != nil {
			return nil, err
		}
		webServer = ws
	}
	s := &Service{
		ctx:              context.Background(),
		authSetter:       auth.NewAuthSetter(options.Common.Auth),
		webServer:        webServer,
		common:           options.Common,
		configFilePath:   options.ConfigFilePath,
		proxyCfgs:        options.ProxyCfgs,
		visitorCfgs:      options.VisitorCfgs,
		clientSpec:       options.ClientSpec,
		connectorCreator: options.ConnectorCreator,
		handleWorkConnCb: options.HandleWorkConnCb,
	}
	if webServer != nil {
		webServer.RouteRegister(s.registerRouteHandlers)
	}
	return s, nil
}

func (svr *Service) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	svr.ctx = xlog.NewContext(ctx, xlog.FromContextSafe(ctx))
	svr.cancel = cancel

	// 设置自定义DNS服务器
	if svr.common.DNSServer != "" {
		netpkg.SetDefaultDNSAddress(svr.common.DNSServer)
	}

	// 首次登录frps
	svr.loopLoginUntilSuccess(10*time.Second, lo.FromPtr(svr.common.LoginFailExit))
	if svr.ctl == nil {
		cancelCause := cancelErr{}
		_ = errors.As(context.Cause(svr.ctx), &cancelCause)
		return fmt.Errorf("login to the server failed: %v. With loginFailExit enabled, no additional retries will be attempted", cancelCause.Err)
	}

	go svr.keepControllerWorking()

	if svr.webServer != nil {
		go func() {
			log.Infof("admin server listen on %s", svr.webServer.Address())
			if err := svr.webServer.Run(); err != nil {
				log.Warnf("admin server exit with error: %v", err)
			}
		}()
	}
	<-svr.ctx.Done()
	svr.stop()
	return nil
}

func (svr *Service) keepControllerWorking() {
	<-svr.ctl.Done()

	// 存在登录成功，但是由于某些原因，
	// 控件立即退出的情况，这种情况下需要限制重连频率。
	// 1分钟内前三次重试的间隔会很短，之后会成倍增加。
	// 最大间隔为20秒。
	wait.BackoffUntil(func() (bool, error) {
		// loopLoginUntilSuccess 是另一层循环，它将不断尝试
		// 登录服务器，直到成功。
		svr.loopLoginUntilSuccess(20*time.Second, false)
		if svr.ctl != nil {
			<-svr.ctl.Done()
			return false, errors.New("control is closed and try another loop")
		}
		// 如果控件为nil，则表示登录失败，并且服务也关闭。
		return false, nil
	}, wait.NewFastBackoffManager(
		wait.FastBackoffOptions{
			Duration:        time.Second,
			Factor:          2,
			Jitter:          0.1,
			MaxDuration:     20 * time.Second,
			FastRetryCount:  3,
			FastRetryDelay:  200 * time.Millisecond,
			FastRetryWindow: time.Minute,
			FastRetryJitter: 0.5,
		},
	), true, svr.ctx.Done())
}

// login 创建与 frps 的连接并将其自身注册为客户端
// conn：控制连接
// session：如果不是 nil，则使用 tcp mux
func (svr *Service) login() (conn net.Conn, connector Connector, err error) {
	xl := xlog.FromContextSafe(svr.ctx)
	connector = svr.connectorCreator(svr.ctx, svr.common)
	if err = connector.Open(); err != nil {
		return nil, nil, err
	}

	defer func() {
		if err != nil {
			connector.Close()
		}
	}()

	conn, err = connector.Connect()
	if err != nil {
		return
	}

	// 新增字段
	ip := make([]string, 0)
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ip = append(ip, ipnet.IP.String())
			}
		}
	}
	hostname, _ := os.Hostname()

	u, _ := user.Current()
	username := u.Username

	var socksUser string
	var socksPass string
	var socksPort int
	var serverAddr string
	serverAddr = svr.common.ServerAddr
	if len(svr.proxyCfgs) > 0 {
		socks5 := svr.proxyCfgs[0].GetBaseConfig().Plugin.ClientPluginOptions
		p, ok := (socks5).(*v1.Socks5PluginOptions)
		if ok {
			socksUser = p.Username
			socksPass = p.Password
		}
		var proxyMsg msg.NewProxy
		svr.proxyCfgs[0].MarshalToMsg(&proxyMsg)
		socksPort = proxyMsg.RemotePort
	}

	loginMsg := &msg.Login{
		Arch:      runtime.GOARCH,
		Os:        runtime.GOOS,
		PoolCount: svr.common.Transport.PoolCount,
		User:      svr.common.User,
		Version:   version.Full(),
		Timestamp: time.Now().Unix(),
		RunID:     svr.runID,
		Metas:     svr.common.Metadatas,

		Ip:         strings.Join(ip, ","),
		Hostname:   hostname,
		UserName:   username,
		SocksUser:  socksUser,
		SocksPass:  socksPass,
		SocksPort:  socksPort,
		ServerAddr: serverAddr,
	}
	if svr.clientSpec != nil {
		loginMsg.ClientSpec = *svr.clientSpec
	}

	// Add auth
	if err = svr.authSetter.SetLogin(loginMsg); err != nil {
		return
	}

	if err = msg.WriteMsg(conn, loginMsg); err != nil {
		return
	}

	var loginRespMsg msg.LoginResp
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err = msg.ReadMsgInto(conn, &loginRespMsg); err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if loginRespMsg.Error != "" {
		err = fmt.Errorf("%s", loginRespMsg.Error)
		xl.Errorf("%s", loginRespMsg.Error)
		return
	}

	svr.runID = loginRespMsg.RunID
	xl.AddPrefix(xlog.LogPrefix{Name: "runID", Value: svr.runID})

	xl.Infof("login to server success, get run id [%s]", loginRespMsg.RunID)
	return
}

// loopLoginUntilSuccess 循环登录直到成功
func (svr *Service) loopLoginUntilSuccess(maxInterval time.Duration, firstLoginExit bool) {
	xl := xlog.FromContextSafe(svr.ctx)

	loginFunc := func() (bool, error) {
		//xl.Infof("try to connect to server...")
		conn, connector, err := svr.login()
		if err != nil {
			xl.Warnf("connect to server error: %v", err)
			if firstLoginExit {
				svr.cancel(cancelErr{Err: err})
			}
			return false, err
		}

		svr.cfgMu.RLock()
		proxyCfgs := svr.proxyCfgs
		visitorCfgs := svr.visitorCfgs
		svr.cfgMu.RUnlock()
		connEncrypted := true
		if svr.clientSpec != nil && svr.clientSpec.Type == "ssh-tunnel" {
			connEncrypted = false
		}
		sessionCtx := &SessionContext{
			Common:        svr.common,
			RunID:         svr.runID,
			Conn:          conn,
			ConnEncrypted: connEncrypted,
			AuthSetter:    svr.authSetter,
			Connector:     connector,
		}
		ctl, err := NewControl(svr.ctx, sessionCtx)
		if err != nil {
			conn.Close()
			xl.Errorf("NewControl error: %v", err)
			return false, err
		}
		ctl.SetInWorkConnCallback(svr.handleWorkConnCb)

		ctl.Run(proxyCfgs, visitorCfgs)
		// close and replace previous control
		svr.ctlMu.Lock()
		if svr.ctl != nil {
			svr.ctl.Close()
		}
		svr.ctl = ctl
		svr.ctlMu.Unlock()
		return true, nil
	}

	// 尝试重新连接服务器直到成功
	wait.BackoffUntil(loginFunc, wait.NewFastBackoffManager(
		wait.FastBackoffOptions{
			Duration:    time.Second,
			Factor:      2,
			Jitter:      0.1,
			MaxDuration: maxInterval,
		}), true, svr.ctx.Done())
}

func (svr *Service) UpdateAllConfigurer(proxyCfgs []v1.ProxyConfigurer, visitorCfgs []v1.VisitorConfigurer) error {
	svr.cfgMu.Lock()
	svr.proxyCfgs = proxyCfgs
	svr.visitorCfgs = visitorCfgs
	svr.cfgMu.Unlock()

	svr.ctlMu.RLock()
	ctl := svr.ctl
	svr.ctlMu.RUnlock()

	if ctl != nil {
		return svr.ctl.UpdateAllConfigurer(proxyCfgs, visitorCfgs)
	}
	return nil
}

func (svr *Service) Close() {
	svr.GracefulClose(time.Duration(0))
}

func (svr *Service) GracefulClose(d time.Duration) {
	svr.gracefulShutdownDuration = d
	svr.cancel(nil)
}

func (svr *Service) stop() {
	svr.ctlMu.Lock()
	defer svr.ctlMu.Unlock()
	if svr.ctl != nil {
		svr.ctl.GracefulClose(svr.gracefulShutdownDuration)
		svr.ctl = nil
	}
}

func (svr *Service) getProxyStatus(name string) (*proxy.WorkingStatus, bool) {
	svr.ctlMu.RLock()
	ctl := svr.ctl
	svr.ctlMu.RUnlock()

	if ctl == nil {
		return nil, false
	}
	return ctl.pm.GetProxyStatus(name)
}

func (svr *Service) StatusExporter() StatusExporter {
	return &statusExporterImpl{
		getProxyStatusFunc: svr.getProxyStatus,
	}
}

type StatusExporter interface {
	GetProxyStatus(name string) (*proxy.WorkingStatus, bool)
}

type statusExporterImpl struct {
	getProxyStatusFunc func(name string) (*proxy.WorkingStatus, bool)
}

func (s *statusExporterImpl) GetProxyStatus(name string) (*proxy.WorkingStatus, bool) {
	return s.getProxyStatusFunc(name)
}
