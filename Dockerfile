#// Copyright (C) 2023 Intel Corporation                                          
#//                                                                               
#// Permission is hereby granted, free of charge, to any person obtaining a copy  
#// of this software and associated documentation files (the "Software"),         
#// to deal in the Software without restriction, including without limitation     
#// the rights to use, copy, modify, merge, publish, distribute, sublicense,      
#// and/or sell copies of the Software, and to permit persons to whom             
#// the Software is furnished to do so, subject to the following conditions:      
#//                                                                               
#// The above copyright notice and this permission notice shall be included       
#// in all copies or substantial portions of the Software.                        
#//                                                                               
#// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS       
#// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,   
#// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL      
#// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES             
#// OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,      
#// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE            
#// OR OTHER DEALINGS IN THE SOFTWARE.                                            
#//                                                                               
#// SPDX-License-Identifier: MIT

FROM ubuntu:16.04
ENV UBUNTU_VERSION=16.04

# Install required packages
RUN dpkg --add-architecture i386 \
    && apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    ca-certificates \
    curl \
    dos2unix \
    wget \
    unzip \
    zip \
    bzip2 \
    xz-utils \
    make \
    unifdef \
    && add-apt-repository -y ppa:ubuntu-toolchain-r/test \
    && add-apt-repository -y ppa:git-core/ppa \
    && apt-get update \
    && apt-get -f install \
    && apt-get update \
    && apt-get install -y \
    gcc-8 \
    g++-8 \
    git \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 1 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-8 1

# Install Clang
ENV CLANG_VERSION=9.0.0
RUN wget -P /tmp  https://releases.llvm.org/$CLANG_VERSION/clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
    && tar -C /opt -xJf /tmp/clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-16.04.tar.xz \
    && mv /opt/clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-16.04 /opt/clang-$CLANG_VERSION \
    && update-alternatives --install /usr/bin/clang clang /opt/clang-$CLANG_VERSION/bin/clang 1 \
    && update-alternatives --install /usr/bin/clang++ clang++ /opt/clang-$CLANG_VERSION/bin/clang++ 1 \
    && rm -rf /tmp/clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-16.04.tar.xz

# Install extra Clang version
ENV CLANG_VERSION_MAJOR=12
ENV CLANG_VERSION=${CLANG_VERSION_MAJOR}.0.0
RUN wget --no-check-certificate -P /tmp https://github.com/llvm/llvm-project/releases/download/llvmorg-$CLANG_VERSION/clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-$UBUNTU_VERSION.tar.xz \
    && tar -C /opt -xJf /tmp/clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-$UBUNTU_VERSION.tar.xz \
    && mv /opt/clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-$UBUNTU_VERSION /opt/clang-$CLANG_VERSION \
    && update-alternatives --install /usr/bin/clang-$CLANG_VERSION clang-$CLANG_VERSION /opt/clang-$CLANG_VERSION/bin/clang 1 \
    && update-alternatives --install /usr/bin/clang++-$CLANG_VERSION clang++-$CLANG_VERSION /opt/clang-$CLANG_VERSION/bin/clang++ 1 \
    && update-alternatives --install /usr/bin/clang-$CLANG_VERSION_MAJOR clang-$CLANG_VERSION_MAJOR /opt/clang-$CLANG_VERSION/bin/clang 1 \
    && update-alternatives --install /usr/bin/clang++-$CLANG_VERSION_MAJOR clang++-$CLANG_VERSION_MAJOR /opt/clang-$CLANG_VERSION/bin/clang++ 1 \
    && rm -rf /tmp/clang+llvm-$CLANG_VERSION-x86_64-linux-gnu-ubuntu-$UBUNTU_VERSION.tar.xz

# Install OpenSSL
ENV OPENSSL_VERSION=1.1.1
RUN wget -P /tmp --no-check-certificate https://www.openssl.org/source/openssl-${OPENSSL_VERSION}k.tar.gz \
    && cd /tmp && tar xvf /tmp/openssl-${OPENSSL_VERSION}k.tar.gz \
    && cd /tmp/openssl-${OPENSSL_VERSION}k \
    && ./config \
    && make \
    #&& make test \
    && make install \
    && rm -rf /tmp/openssl-${OPENSSL_VERSION}k*

ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64

# Install NASM
ENV NASM_VERSION=2.15.05
RUN wget -P /tmp --no-check-certificate https://www.nasm.us/pub/nasm/releasebuilds/$NASM_VERSION/nasm-$NASM_VERSION.tar.bz2 \
    && cd /tmp && tar xjvf /tmp/nasm-$NASM_VERSION.tar.bz2 \
    && cd /tmp/nasm-$NASM_VERSION \
    && ./autogen.sh \
    && ./configure --prefix="/opt" --bindir="/usr/bin" \
    && make \
    && make install \
    && rm -rf /tmp/nasm-$NASM_VERSION.*

# Install Python3
RUN apt install -y build-essential checkinstall \
    && apt-get -y install zlib1g-dev \
    && wget -P /tmp --no-check-certificate https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tar.xz \
    && wget -P /tmp --no-check-certificate https://bootstrap.pypa.io/pip/3.8/get-pip.py -o get-pip.py \
    && cd /tmp && tar -xvf Python-3.8.1.tar.xz \
    && cd /tmp/Python-3.8.1 \
    && ./configure \
    && make altinstall \
    && update-alternatives --install /usr/bin/python3.8 python3.8 /usr/local/bin/python3.8 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3 1 \
    && update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.8 1 \
    && python3.8 /tmp/get-pip.py \
    && rm -rf /tmp/get-pip.py /tmp/Python-3.8.1*

# Install CMake
RUN pip uninstall --yes setuptools \
    && pip install setuptools>=65.5.1 \
    && pip install cmake==3.18 \
    && update-alternatives --install /usr/bin/cmake cmake /usr/local/bin/cmake 1 \
