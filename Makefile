CURRET_DIR=$(shell pwd)
BINARY=./build/sgn
BUILD=CGO_ENABLED=1 go build
OUT_DIR=${CURRET_DIR}/build
BUILD_FLAGS=-trimpath -buildvcs=false -ldflags="-s -w -X github.com/EgeBalci/sgn/config.Version=$$(git log --pretty=format:'v2.0.1.%at-%h' -n 1)" 
STATIC_BUILD_FLAGS=-trimpath -buildvcs=false -ldflags="-extldflags=-static -s -w -X github.com/EgeBalci/sgn/config.Version=$$(git log --pretty=format:'v2.0.1.%at-%h' -n 1)" 

# Builds the project
default:
	${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/
# Builds the project with full static linking
static:
	${BUILD} ${STATIC_BUILD_FLAGS} -o ${OUT_DIR}/
# Installs our project: copies binaries
install:
	go install ${BUILD_FLAGS} github.com/EgeBalci/sgn@latest
386:
	GOARCH=386 ${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/
linux_amd64:
	GOOS=linux  GOARCH=amd64 ${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/
linux_386:
	GOOS=linux  GOARCH=386 ${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/
windows_amd64:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CGO_LDFLAGS="-lkeystone -L${CURRET_DIR}/build/lib/dll/" CXX=x86_64-w64-mingw32-g++ CC=x86_64-w64-mingw32-gcc go build -ldflags="-s -w" -trimpath -o ${OUT_DIR}/sgn.exe
windows_386:
	GOOS=windows GOARCH=386 CGO_ENABLED=1 CGO_LDFLAGS="-lkeystone -L${CURRET_DIR}/build/lib32/dll/" CXX=i686-w64-mingw32-g++ CC=i686-w64-mingw32-gcc go build -ldflags="-s -w" -trimpath -o ${OUT_DIR}/sgn32.exe
darwin_amd64:
	GOOS=darwin GOARCH=amd64 ${BUILD} ${BUILD_FLAGS} -o ${OUT_DIR}/ 

# Cleans our project: deletes binaries
clean:
	rm -rf ./build

.PHONY: clean install
