# Scan Framework
* 针对ip快速、易用的扫描框架
* 自动挖掘web端口
* 通过插件对ip进行漏洞扫描

```
python Scan.py
 ____                    _____                                            _
/ ___|  ___ __ _ _ __   |  ___| __ __ _ _ __ ___   _____      _____  _ __| | __
\___ \ / __/ _` | '_ \  | |_ | '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
 ___) | (_| (_| | | | | |  _|| | | (_| | | | | | |  __/\ V  V / (_) | |  |   <
|____/ \___\__,_|_| |_| |_|  |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\  __author__="Jaqen"

Usage: python Scan.py 1.1.1 or 1.1.1.1-1.1.1.5 or ip.ini
```
# 文件结构
* /lib/config.py 配置文件，配置一些全局变量，增加变量需引入
* /plugins/  插件目录，将写好的插件放在此目录下就可以使用

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
    if Domain:
        for domain in Domain:
            result.append(attack(domain))
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
        #
        return result
    except Exception, e:
        logging.error(ip+' '+str(e))
        pass
```

# docker测试环境
![](https://github.com/white-cell/Scan-Framework/blob/master/run1.jpg)  
# 实战
![](https://github.com/white-cell/Scan-Framework/blob/master/run2.jpg)  
