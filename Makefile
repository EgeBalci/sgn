normal:
	go build -ldflags="-s -w" -trimpath -o sgn
386:
	CGO_ENABLED=1 GOARCH=386 go build -ldflags="-s -w" -trimpath -o sgn
linux_amd64:
	GOOS=linux CGO_ENABLED=1 GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o sgn
linux_386:
	GOOS=linux CGO_ENABLED=1 GOARCH=386 go build -ldflags="-s -w" -trimpath -o sgn
windows_amd64:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CGO_LDFLAGS="-lkeystone -L`pwd`/build/lib/" CXX=x86_64-w64-mingw32-g++ CC=x86_64-w64-mingw32-gcc go build -ldflags="-s -w" -trimpath -o sgn.exe
windows_386:
	GOOS=windows GOARCH=386 CGO_ENABLED=1 CGO_LDFLAGS="-lkeystone -L`pwd`/build/lib32/" CXX=i686-w64-mingw32-g++ CC=i686-w64-mingw32-gcc go build -ldflags="-s -w" -trimpath -o sgn32.exe
darwin:
	GOOS=darwin CGO_ENABLED=1 CGO_LDFLAGS="-lkeystone -L/usr/lib/" go build -ldflags="-s -w" -trimpath -o sgn
