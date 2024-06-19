# coro_socks
[![License](https://img.shields.io/npm/l/mithril.svg)](https://github.com/xukeawsl/coro_socks/blob/master/LICENSE)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/0578118cbfb246d0ab6b74efc984c754)](https://app.codacy.com/gh/xukeawsl/coro_socks/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

A high-performance socks5 server implemented using C++20 asio coroutine and [asiomp](https://github.com/xukeawsl/asiomp)

## Protocol support

* "No Auth" mode

* User/Password authentication

* Support for the `CONNECT` command

* Support for the `UDP ASSOCIATE` command

* Support IPv4/IPv6 and DNS resolution

## Features

* Only supports Linux platform

* Using multiple processes and coroutines

* Support daemon processes mode

* Support docker-compose deployment

## Build with CMake

```bash
git clone --recurse-submodules https://github.com/xukeawsl/coro_socks.git
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

## Configuration

```yaml
server:
  # listening address (default 0.0.0.0)
  address: '0.0.0.0'

  # listening port (default 1080)
  port: 1080

  # when num == 0, use default worker_process_num
  # when num == 1, use singal worker process mode
  # when num  > 1, use master-worker process mode
  worker_process_num: 0

  # work in daemon mode (default false)
  daemon: false

  protocol:
    # keep alive time (default 30s)
    keep_alive_time: 30

    # duration for check keep alive (default 1s)
    check_duration: 1

    # enable username/password authentication (default false)
    auth: false

    # setting your username and password when enable auth
    credentials:
      - username: 'coro_socks_user1'
        password: 'coro_socks_pswd1'
      - username: 'coro_socks_user2'
        password: 'coro_socks_pswd2'
```

## Deploy with docker-compose

```bash
git clone https://github.com/xukeawsl/coro_socks.git
cd docker
docker-compose up -d
```