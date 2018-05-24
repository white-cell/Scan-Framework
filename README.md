# Scan Framework
* 针对ip快速、易用的扫描框架
* 自动挖掘web端口
* 通过插件对ip进行漏洞扫描
* 基于python2.7
* 基于masscan

```
python Scan.py
 ____                    _____                                            _
/ ___|  ___ __ _ _ __   |  ___| __ __ _ _ __ ___   _____      _____  _ __| | __
\___ \ / __/ _` | '_ \  | |_ | '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
 ___) | (_| (_| | | | | |  _|| | | (_| | | | | | |  __/\ V  V / (_) | |  |   <
|____/ \___\__,_|_| |_| |_|  |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\  __author__="Jaqen"

PLUGINS: ['rsync', 'tomcat_vul', 'zookeeper', 'mongodb', 'weblogic_crackpass', 'weblogic2018', 'st2-045', 'memcache', 'redis', 'st2_eval', 'jboss_vul', 'resin_fileread', 'rmi_rce', 'ms17-010', 'weblogic_ssrf', 'axis_vul', 'glassfish_vul', 'web_weakfile']
usage: Scan.py [options]

*针对ip快速、易用的扫描框架*

optional arguments:
  -h, --help        show this help message and exit
  -i IP             1.1 or 1.1.1 or 1.1.1.1-1.1.1.5 or ip.ini
  -P PLUGIN SELECT  select which plugin you want by -P scriptname,scriptname , default use None
  -p SCANPORT       select ports you want to scan, default use 0-65535,
  -t THREADS        Num of scan threads, 100 by default
  -T TIMEOUT        Num of scan timeout, 5 by default
```
# 文件结构
* /lib/config.py 配置文件，配置一些全局变量(详情查看文件)，增加变量需引入
* /lib/masscan/ 自带的masscan，只能在linux64和windows下使用，其他环境需自己安装masscan
* /plugins/  插件目录，将写好的插件放在此目录下就可以使用
* /result.txt 每次运行的结果重新排版记录在里面
* /run.log 记录上一次运行过程中的报错日志


# 插件格式
* WEB类漏洞插件格式
``` python
# coding:utf-8
import logging
import lib.requests as requests
import random
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)
def exploit(ip):
    result = []
    if Domain:
        for domain in Domain:
            #poc
            result.append('%s >>>> 存在xxx漏洞'%domain)
        if len(result):
            return result
```
* 端口类漏洞插件格式
``` python
# coding:utf-8
import socket
import logging
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)
def exploit(ip):
    port = PORT
    try:
        #poc
        if 存在漏洞:
            return '%s:%s >>>> 存在xxx漏洞'%(ip,port)
    except Exception, e:
        logging.error(ip+' '+str(e))
        pass
```

# example
* python Scan.py -i 192.168.216.6
* python Scan.py -i 192.168.216
* python Scan.py -i ip.ini
* python Scan.py -i 192.168.216.6 -p 79-8081
* python Scan.py -i 192.168.216.6 -p 80,443
* python Scan.py -i 192.168.216.6 -p 80
* python Scan.py -i 192.168.216.6 -P st2-045,st2_eval
* python Scan.py -i 192.168.216.6 -P all
* python Scan.py -i 192.168.216.6 -T 5 -t 100

# docker测试环境
![](https://github.com/white-cell/Scan-Framework/blob/master/run1.jpg)  
# 实战
![](https://github.com/white-cell/Scan-Framework/blob/master/run2.jpg)  
