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
	&& echo "deb http://ppa.launchpadcontent.net/ubuntu-toolchain-r/test/ubuntu xenial main" > /etc/apt/sources.list.d/ubuntu-toolchain-r.list \
    && echo "deb http://ppa.launchpadcontent.net/git-core/ppa/ubuntu xenial main" > /etc/apt/sources.list.d/git-core.list \
    && curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xE363C90F8F1B6217" | apt-key add - \
    && curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xA1715D88E1DF1F24" | apt-key add - \
    && curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x2C277A0A352154E5" | apt-key add - \
    && curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x1E9377A2BA9EF27F" | apt-key add - \
    && apt-get update \
    && apt-get install -y \
    gcc-8 \
    g++-8 \
    git \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 1 \
    && update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-8 1 \
    && rm -rf /var/lib/apt/lists/*

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
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/openssl-${OPENSSL_VERSION}k*
ENV LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64

# Install NASM
ENV NASM_VERSION=2.16.02
RUN wget -P /tmp --no-check-certificate https://www.nasm.us/pub/nasm/releasebuilds/$NASM_VERSION/nasm-$NASM_VERSION.tar.bz2 \
    && cd /tmp && tar xjvf /tmp/nasm-$NASM_VERSION.tar.bz2 \
    && cd /tmp/nasm-$NASM_VERSION \
    && ./autogen.sh \
    && ./configure --prefix="/opt" --bindir="/usr/bin" \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/nasm-$NASM_VERSION.*

# Install Python3
RUN apt-get update \
    && apt install -y build-essential checkinstall \
    && apt-get -y install zlib1g-dev \
    && wget -P /tmp --no-check-certificate https://www.python.org/ftp/python/3.13.9/Python-3.13.9.tar.xz \
    && cd /tmp && tar -xvf Python-3.13.9.tar.xz \
    && cd /tmp/Python-3.13.9 \
    && ./configure --with-openssl=/usr/local --with-openssl-rpath=auto \
    && make -j"$(nproc)" \
    && make altinstall \
    && update-alternatives --install /usr/bin/python python /usr/local/bin/python3.13 1 \
    && update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.13 1 \
    && rm -rf /tmp/Python-3.13.9* \
    && rm -rf /var/lib/apt/lists/*

# Update pip, setuptools & install CMake 
RUN pip3.13 install --upgrade pip \
    && pip3.13 uninstall --yes setuptools \
    && pip3.13 install "setuptools>=78.1.1" \
    && pip3.13 install cmake==3.18 \
    && update-alternatives --install /usr/bin/cmake cmake /usr/local/bin/cmake 1

# Install clang 16
ENV CLANG_VERSION=16.0.3
RUN git clone --depth 1 --branch llvmorg-$CLANG_VERSION https://github.com/llvm/llvm-project.git /tmp/llvm-project \
    && mkdir -p /opt/clang-$CLANG_VERSION && cd /opt/clang-$CLANG_VERSION \
    && cmake -DCMAKE_BACKWARDS_COMPATIBILITY=2.9 -DPython3_FIND_STRATEGY=LOCATION -DPython3_EXECUTABLE=/usr/bin/python3 \
    -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" -DCOMPILER_RT_BUILD_SANITIZERS=ON -DLLDB_INCLUDE_TESTS=OFF \
    -DCMAKE_CXX_COMPILER=/usr/bin/g++-8 -DCMAKE_C_COMPILER=/usr/bin/gcc-8 -DCMAKE_BUILD_TYPE=Release -G "Unix Makefiles" /tmp/llvm-project/llvm \
    && make -j"$(nproc)" \
    && update-alternatives --install /usr/bin/clang-$CLANG_VERSION clang-$CLANG_VERSION /opt/clang-$CLANG_VERSION/bin/clang 1 \
    && update-alternatives --install /usr/bin/clang++-$CLANG_VERSION clang++-$CLANG_VERSION /opt/clang-$CLANG_VERSION/bin/clang++ 1 \
    && update-alternatives --install /usr/bin/clang-16 clang-16 /opt/clang-$CLANG_VERSION/bin/clang 1 \
    && update-alternatives --install /usr/bin/clang++-16 clang++-16 /opt/clang-$CLANG_VERSION/bin/clang++ 1 \
    && rm -rf /tmp/llvm-project