#!/usr/bin/env python
# coding:utf-8
import logging
import lib.requests as requests
import random
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def plugin_info():
    return {
        "name": "weblogic_crackpass",
        "info": "Weblogic弱口令",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def exploit(ip):
    result = []
    if Domain:
        for domain in Domain:
            try:
                ssrf_url = domain+'/uddiexplorer/SearchPublicRegistries.jsp'
                resp = requests.get(ssrf_url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
            except Exception,e:
                logging.error(e)
                continue
            if resp.status_code == 200 and "oracle_logo.gif" in resp.text:
                result.append('%s >>>> 存在Weblogic ssrf漏洞'%ssrf_url)
        if len(result):
            return result