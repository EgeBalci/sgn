normal:
	go build -ldflags="-s -w" -trimpath -o sgn
386:
	CGO_ENABLED=1 GOARCH=386 go build -ldflags="-s -w" -trimpath -o sgn
