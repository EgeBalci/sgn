CURRET_DIR=$(shell pwd)
BUILD=CGO_ENABLED=1 go build
OUT_DIR=${CURRET_DIR}/build
BUILD_FLAGS=-trimpath -buildvcs=false -ldflags="-extldflags=-static -s -w -X github.com/EgeBalci/sgn/config.Version=$$(git log --pretty=format:'v2.0.1.%at-%h' -n 1)" 

default:
	${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/
386:
	CGO_ENABLED=1 GOARCH=386 ${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/
linux_amd64:
	GOOS=linux  GOARCH=amd64 ${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/
linux_386:
	GOOS=linux  GOARCH=386 ${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/
windows_amd64:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CGO_LDFLAGS="-lkeystone -L${CURRET_DIR}/build/lib/" CXX=x86_64-w64-mingw32-g++ CC=x86_64-w64-mingw32-gcc go build -ldflags="-extldflags=-static -s -w" -trimpath -o ${OUT_DIR}/sgn.exe
windows_386:
	GOOS=windows GOARCH=386 CGO_ENABLED=1 CGO_LDFLAGS="-lkeystone -L${CURRET_DIR}/build/lib32/" CXX=i686-w64-mingw32-g++ CC=i686-w64-mingw32-gcc go build -ldflags="-extldflags=-static -s -w" -trimpath -o ${OUT_DIR}/sgn32.exe
darwin:
	GOOS=darwin GOARCH=amd64 ${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/ 
