FROM ubuntu:22.04

RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list

# Install Required Packages and Clean up APT when done.
RUN apt-get update \
    && apt-get install -y --no-install-recommends  g++ cmake make git locales \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && locale-gen en_US.UTF-8

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    GIT_SSL_NO_VERIFY=1 \
    SOCKS_ROOT=/root/coro_socks

RUN git clone --recurse-submodules https://github.com/xukeawsl/coro_socks.git $SOCKS_ROOT

WORKDIR $SOCKS_ROOT

RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=Release .. && make

CMD cd build && /bin/bash -c "./coro_socks"