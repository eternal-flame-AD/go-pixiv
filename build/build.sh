env GOOS=linux GOARCH=386 go build -ldflags="-s -w" -o go-pixiv-linux-386 -v github.com/eternal-flame-AD/go-pixiv
env GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o go-pixiv-linux-amd64 -v github.com/eternal-flame-AD/go-pixiv
env GOOS=windows GOARCH=386 go build -ldflags="-s -w" -o go-pixiv-windows-386.exe -v github.com/eternal-flame-AD/go-pixiv
env GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o go-pixiv-windows-amd64.exe -v github.com/eternal-flame-AD/go-pixiv
upx --lzma go-pixiv-*
