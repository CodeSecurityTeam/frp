frps-linux:
	env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}" -tags frps -o bin/frps ./cmd/frps

frps-darwin:
	env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}" -tags frps -o bin/frps ./cmd/frps

frps-windows:
	env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}" -tags frps -o bin/frps.exe ./cmd/frps

frpc-darwin:
	env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}" -tags frpc -o bin/frpc ./cmd1/frpc

frpc-linux:
	env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}" -tags frpc -o bin/frpc ./cmd1/frpc

frpc-windows:
	env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}" -tags frpc -o bin/frpc.exe ./cmd1/frpc

frpc-windows-x:
	env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 garble build -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}" -tags frpc -o bin/frpc.exe ./cmd1/frpc

frpc-linux-x:
	env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 garble build -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}" -tags frpc -o bin/frpc ./cmd1/frpc

frpc-darwin-x:
	env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 garble build -ldflags "-s -w" -gcflags="all=-trimpath=${PWD}" -asmflags="all=-trimpath=${PWD}" -tags frpc -o bin/frpc ./cmd1/frpc
