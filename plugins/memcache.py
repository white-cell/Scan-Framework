# coding:utf-8
import socket
import logging
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def plugin_info():
    return {
        "name": "memcache",
        "info": "Memcache未授权",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def exploit(ip):
    port = PORT
    try:
        socket.setdefaulttimeout(TIME_OUT)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send("stats\r\n")
        result = s.recv(1024)
        if "STAT version" in result:
            return '%s:%s >>>> 存在Memcache未授权访问漏洞'%(ip,port)
    except Exception, e:
        logging.error(ip+' '+str(e))
        pass