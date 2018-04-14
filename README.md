# Scan Framework
* 针对ip快速、易用的扫描框架
* 自动挖掘web端口
* 通过插件对ip进行漏洞扫描
* 基于python2.7

```
python Scan.py
 ____                    _____                                            _
/ ___|  ___ __ _ _ __   |  ___| __ __ _ _ __ ___   _____      _____  _ __| | __
\___ \ / __/ _` | '_ \  | |_ | '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
 ___) | (_| (_| | | | | |  _|| | | (_| | | | | | |  __/\ V  V / (_) | |  |   <
|____/ \___\__,_|_| |_| |_|  |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\  __author__="Jaqen"

PLUGINS: ['crack_redis', 'tomcatgetshell', 'st2-045', 'st2_eval']
usage: Scan.py [options]

*针对ip快速、易用的扫描框架*

optional arguments:
  -h, --help        show this help message and exit
  -i IP             1.1 or 1.1.1 or 1.1.1.1-1.1.1.5 or ip.ini
  -P PLUGIN SELECT  select which plugin you want by -P scriptname,scriptname , default use all
  --noweb           select this to pass find domain and pass web plugins
  -p WEBPORT        select ports you want to Brute force, default use 70-16000
  -t THREADS        Num of scan threads, 100 by default
  -T TIMEOUT        Num of scan timeout, 5 by default
```
# 文件结构
* /lib/config.py 配置文件，配置一些全局变量，增加变量需引入
* /plugins/  插件目录，将写好的插件放在此目录下就可以使用
* /result.txt 每次运行的结果都会存在里面

# 插件格式
* WEB类漏洞插件格式
``` python
# coding:utf-8
import logging
from lib.config import (
    PASSWORD_DIC, TIME_OUT, MY_PROXY, USER_AGENT_LIST
)
def exploit(ip):
    result = []
    if FindDomain_flag:
        if Domain:
            for domain in Domain:
                #poc
                result.append('%s >>>> 存在xxx漏洞'%domain)
            if len(result):
                return result
```
* 端口类漏洞插件格式
```python
# coding:utf-8
import socket
import logging
from lib.config import (
    PASSWORD_DIC, TIME_OUT, MY_PROXY, USER_AGENT_LIST
)
def exploit(ip):
    port = 端口
    try:
        #poc
        if 存在漏洞:
            return '%s >>>> 存在xxx漏洞'%ip
    except Exception, e:
        logging.error(ip+' '+str(e))
        pass
```

# example
* python Scan.py -i 192.168.216.6
* python Scan.py -i 192.168.216.6 -p 79-8081
* python Scan.py -i 192.168.216.6 -p 80,443
* python Scan.py -i 192.168.216.6 -P st2-045,st2_eval
* python Scan.py -i 192.168.216.6 --noweb

# docker测试环境
![](https://github.com/white-cell/Scan-Framework/blob/master/run1.jpg)  
# 实战
![](https://github.com/white-cell/Scan-Framework/blob/master/run2.jpg)  
