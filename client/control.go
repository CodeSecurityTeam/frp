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
	"net"
	"sync/atomic"
	"time"

	"github.com/xx/xxx/client/proxy"
	"github.com/xx/xxx/client/visitor"
	"github.com/xx/xxx/pkg/auth"
	v1 "github.com/xx/xxx/pkg/config/v1"
	"github.com/xx/xxx/pkg/msg"
	"github.com/xx/xxx/pkg/transport"
	netpkg "github.com/xx/xxx/pkg/util/net"
	"github.com/xx/xxx/pkg/util/wait"
	"github.com/xx/xxx/pkg/util/xlog"
)

type SessionContext struct {
	// 客户端通用配置
	Common *v1.ClientCommonConfig

	// 从 frps 获取的唯一 ID。
	// 重新连接时应将其附加到登录消息中。
	RunID string
	//底层控制连接。一旦 conn 关闭，msgDispatcher 和整个 Control 都会退出。
	Conn net.Conn
	// 指示连接是否加密
	ConnEncrypted bool
	// 根据所选方法设置身份验证
	AuthSetter auth.Setter
	// 连接器用于创建新的连接，可以是真实的TCP连接，也可以是虚拟流。
	Connector Connector
}

type Control struct {
	// service context
	ctx context.Context
	xl  *xlog.Logger

	// session context
	sessionCtx *SessionContext

	// manage all proxies
	pm *proxy.Manager

	// manage all visitors
	vm *visitor.Manager

	doneCh chan struct{}

	// time.Time，上次收到 Pong 消息的时间
	lastPong atomic.Value

	// msgTransporter的作用和HTTP2类似。
	// 它允许在同一个控制连接上同时发送多条消息。
	// 服务端的响应消息会根据laneKey和消息类型，分发到相应的等待goroutine中。
	msgTransporter transport.MessageTransporter

	// msgDispatcher 是控制连接的包装器。
	// 它提供了发送消息的通道，您可以注册处理程序以根据各自的类型处理消息。
	msgDispatcher *msg.Dispatcher
}

func NewControl(ctx context.Context, sessionCtx *SessionContext) (*Control, error) {
	// new xlog instance
	ctl := &Control{
		ctx:        ctx,
		xl:         xlog.FromContextSafe(ctx),
		sessionCtx: sessionCtx,
		doneCh:     make(chan struct{}),
	}
	ctl.lastPong.Store(time.Now())

	if sessionCtx.ConnEncrypted {
		cryptoRW, err := netpkg.NewCryptoReadWriter(sessionCtx.Conn, []byte(sessionCtx.Common.Auth.Token))
		if err != nil {
			return nil, err
		}
		ctl.msgDispatcher = msg.NewDispatcher(cryptoRW)
	} else {
		ctl.msgDispatcher = msg.NewDispatcher(sessionCtx.Conn)
	}
	ctl.registerMsgHandlers()
	ctl.msgTransporter = transport.NewMessageTransporter(ctl.msgDispatcher.SendChannel())

	ctl.pm = proxy.NewManager(ctl.ctx, sessionCtx.Common, ctl.msgTransporter)
	ctl.vm = visitor.NewManager(ctl.ctx, sessionCtx.RunID, sessionCtx.Common, ctl.connectServer, ctl.msgTransporter)
	return ctl, nil
}

func (ctl *Control) Run(proxyCfgs []v1.ProxyConfigurer, visitorCfgs []v1.VisitorConfigurer) {
	go ctl.worker()

	// start all proxies
	ctl.pm.UpdateAll(proxyCfgs)

	// start all visitors
	ctl.vm.UpdateAll(visitorCfgs)
}

func (ctl *Control) SetInWorkConnCallback(cb func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool) {
	ctl.pm.SetInWorkConnCallback(cb)
}

func (ctl *Control) handleReqWorkConn(_ msg.Message) {
	xl := ctl.xl
	workConn, err := ctl.connectServer()
	if err != nil {
		xl.Warnf("start new connection to server error: %v", err)
		return
	}

	m := &msg.NewWorkConn{
		RunID: ctl.sessionCtx.RunID,
	}
	if err = ctl.sessionCtx.AuthSetter.SetNewWorkConn(m); err != nil {
		xl.Warnf("error during NewWorkConn authentication: %v", err)
		workConn.Close()
		return
	}
	if err = msg.WriteMsg(workConn, m); err != nil {
		xl.Warnf("work connection write to server error: %v", err)
		workConn.Close()
		return
	}

	var startMsg msg.StartWorkConn
	if err = msg.ReadMsgInto(workConn, &startMsg); err != nil {
		xl.Tracef("work connection closed before response StartWorkConn message: %v", err)
		workConn.Close()
		return
	}
	if startMsg.Error != "" {
		xl.Errorf("StartWorkConn contains error: %s", startMsg.Error)
		workConn.Close()
		return
	}

	// dispatch this work connection to related proxy
	ctl.pm.HandleWorkConn(startMsg.ProxyName, workConn, &startMsg)
}

func (ctl *Control) handleNewProxyResp(m msg.Message) {
	xl := ctl.xl
	inMsg := m.(*msg.NewProxyResp)
	// 服务器将向每个 NewProxy 消息返回 NewProxyResp 消息。
	// 如果没有错误，则启动新的代理处理程序
	err := ctl.pm.StartProxy(inMsg.ProxyName, inMsg.RemoteAddr, inMsg.Error)
	if err != nil {
		xl.Warnf("[%s] start error: %v", inMsg.ProxyName, err)
	} else {
		xl.Infof("[%s] start proxy success", inMsg.ProxyName)
	}
}

func (ctl *Control) handleNatHoleResp(m msg.Message) {
	xl := ctl.xl
	inMsg := m.(*msg.NatHoleResp)

	// 将 NatHoleResp 消息发送到相关代理。
	ok := ctl.msgTransporter.DispatchWithType(inMsg, msg.TypeNameNatHoleResp, inMsg.TransactionID)
	if !ok {
		xl.Tracef("dispatch NatHoleResp message to related proxy error")
	}
}

func (ctl *Control) handlePong(m msg.Message) {
	xl := ctl.xl
	inMsg := m.(*msg.Pong)

	if inMsg.Error != "" {
		xl.Errorf("Pong message contains error: %s", inMsg.Error)
		ctl.closeSession()
		return
	}
	ctl.lastPong.Store(time.Now())
	xl.Debugf("receive heartbeat from server")
}

// closeSession 关闭控制连接
func (ctl *Control) closeSession() {
	ctl.sessionCtx.Conn.Close()
	ctl.sessionCtx.Connector.Close()
}

func (ctl *Control) Close() error {
	return ctl.GracefulClose(0)
}

func (ctl *Control) GracefulClose(d time.Duration) error {
	ctl.pm.Close()
	ctl.vm.Close()

	time.Sleep(d)

	ctl.closeSession()
	return nil
}

// Done 返回一个通道，该通道将在所有资源释放后关闭
func (ctl *Control) Done() <-chan struct{} {
	return ctl.doneCh
}

// connectServer 返回一个新连接给 frps
func (ctl *Control) connectServer() (net.Conn, error) {
	return ctl.sessionCtx.Connector.Connect()
}

func (ctl *Control) registerMsgHandlers() {
	ctl.msgDispatcher.RegisterHandler(&msg.ReqWorkConn{}, msg.AsyncHandler(ctl.handleReqWorkConn))
	ctl.msgDispatcher.RegisterHandler(&msg.NewProxyResp{}, ctl.handleNewProxyResp)
	ctl.msgDispatcher.RegisterHandler(&msg.NatHoleResp{}, ctl.handleNatHoleResp)
	ctl.msgDispatcher.RegisterHandler(&msg.Pong{}, ctl.handlePong)
}

// headerWorker 向服务器发送心跳并检查心跳超时。
func (ctl *Control) heartbeatWorker() {
	xl := ctl.xl

	if ctl.sessionCtx.Common.Transport.HeartbeatInterval > 0 {
		// Send heartbeat to server.
		sendHeartBeat := func() (bool, error) {
			xl.Debugf("send heartbeat to server")
			pingMsg := &msg.Ping{}
			if err := ctl.sessionCtx.AuthSetter.SetPing(pingMsg); err != nil {
				xl.Warnf("error during ping authentication: %v, skip sending ping message", err)
				return false, err
			}
			_ = ctl.msgDispatcher.Send(pingMsg)
			return false, nil
		}

		go wait.BackoffUntil(sendHeartBeat,
			wait.NewFastBackoffManager(wait.FastBackoffOptions{
				Duration:           time.Duration(ctl.sessionCtx.Common.Transport.HeartbeatInterval) * time.Second,
				InitDurationIfFail: time.Second,
				Factor:             2.0,
				Jitter:             0.1,
				MaxDuration:        time.Duration(ctl.sessionCtx.Common.Transport.HeartbeatInterval) * time.Second,
			}),
			true, ctl.doneCh,
		)
	}

	// Check 心跳超时
	if ctl.sessionCtx.Common.Transport.HeartbeatInterval > 0 && ctl.sessionCtx.Common.Transport.HeartbeatTimeout > 0 {
		go wait.Until(func() {
			if time.Since(ctl.lastPong.Load().(time.Time)) > time.Duration(ctl.sessionCtx.Common.Transport.HeartbeatTimeout)*time.Second {
				xl.Warnf("heartbeat timeout")
				ctl.closeSession()
				return
			}
		}, time.Second, ctl.doneCh)
	}
}

func (ctl *Control) worker() {
	go ctl.heartbeatWorker()
	go ctl.msgDispatcher.Run()

	<-ctl.msgDispatcher.Done()
	ctl.closeSession()

	ctl.pm.Close()
	ctl.vm.Close()
	close(ctl.doneCh)
}

func (ctl *Control) UpdateAllConfigurer(proxyCfgs []v1.ProxyConfigurer, visitorCfgs []v1.VisitorConfigurer) error {
	ctl.vm.UpdateAll(visitorCfgs)
	ctl.pm.UpdateAll(proxyCfgs)
	return nil
}
