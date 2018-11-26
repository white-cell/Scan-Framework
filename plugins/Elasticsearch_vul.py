#!/usr/bin/env python
# coding:utf-8
import logging
import lib.requests as requests
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def plugin_info():
    return {
        "name": "Elasticsearch",
        "info": "Elasticsearch",
        "Author":"Jaqen",
        "Create_date":"2018-11-26"
    }

def exploit(ip):
    result = []
    if Domain:
        for domain in Domain:
            try:
                url = domain+'/'
                resp = requests.get(url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
            except Exception,e:
                logging.error(e)
                continue
            if "You Know, for Search" in resp.text:
                result.append('%s/ >>>> 发现存在Elasticsearch'%domain)
        if len(result):
            return result