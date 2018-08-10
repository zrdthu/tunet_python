---
layout:     post
title:      TUNet Python command-line client
author:     zrd
date:       2018-08-09
---

# TUNet Python command-line client

仅校内认证比较奇怪，具体表现为：即使下线成功，下线后仍能查询到在线账户信息，`usereg`中也能查到对应的ip，但是不能上网。此时可以使用`-f`选项强制重新登录。

    usage: python3 portal.py [-h] [-a {login,logout,check_status}] [-u USERNAME]
                 [-p PASSWORD] [-m MAX_RETRIES] [-t INTERVAL] [-l] [-f]
                 [-d DAEMON]

    optional arguments:
    -h, --help            show this help message and exit
    -a {login,logout,check_status}, --action {login,logout,check_status}
                            action to choose, default login
    -u USERNAME, --username USERNAME
                            username of account
    -p PASSWORD, --password PASSWORD
                            password of account
    -m MAX_RETRIES, --max-retries MAX_RETRIES
                            number of retries after failure, default 5
    -t INTERVAL, --interval INTERVAL
                            interval of retries in seconds, default 30
    -l, --local-only      Tsinghua connections only, without access to the
                            internet
    -f, --force           login/out without checking online status
    -d DAEMON, --daemon DAEMON
                            run in daemon mode, recheck interval in seconds,
                            default 0 for non-daemon mode


> 2018.08.10 
>   增加 daemon mode (for Linux)