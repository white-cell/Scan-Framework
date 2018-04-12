# coding:utf-8
import socket
import logging
from lib.config import (
    PASSWORD_DIC, TIME_OUT, MY_PROXY, USER_AGENT_LIST
)

def get_plugin_info():
    return {
        "name": "crack_redis",
        "info": "redis未授权或弱口令",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def exploit(ip):
    port = 6379
    try:
        socket.setdefaulttimeout(TIME_OUT)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        s.send("INFO\r\n")
        result = s.recv(1024)
        if "redis_version" in result:
            return "%s:%s >>>> 存在redis未授权访问"%(ip,port)
        elif "Authentication" in result:
            for password in PASSWORD_DIC:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, int(port)))
                s.send("AUTH %s\r\n" % (password))
                result = s.recv(1024)
                if '+OK' in result:
                    return "%s:%s >>>> 存在弱口令，密码：%s" % (ip, port, password)
    except Exception, e:
        logging.error(ip+' '+str(e))
        pass
