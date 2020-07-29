FROM ubuntu:18.04
RUN apt-get update && apt-get -y install wget git cmake build-essential libcapstone-dev gcc-multilib g++-multilib python3 time
WORKDIR /root/
RUN git clone https://github.com/EgeBalci/keystone
RUN mkdir keystone/build
WORKDIR /root/keystone/build
RUN ../make-share.sh
RUN cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="AArch64;X86" -G "Unix Makefiles" ..
RUN make -j8
#RUN ../make-lib.sh
#RUN cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DLLVM_TARGETS_TO_BUILD="AArch64, X86" -G "Unix Makefiles" ..
#RUN make -j8
RUN wget https://golang.org/dl/go1.14.6.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.14.6.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
RUN make install
RUN ldconfig
ENV GOPATH=/root
RUN go get -v -u github.com/egebalci/sgn
ENTRYPOINT ["/root/bin/sgn"]
