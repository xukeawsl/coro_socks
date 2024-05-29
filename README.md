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