# coding:utf-8
import socket
import logging
import re
import time
import hashlib
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def plugin_info():
    return {
        "name":"rsync未授权访问与弱验证",
        "info":"可以通过rsync服务下载服务器上敏感数据",
        "author":"nearg1e@ysrc"
    }

def hex2str(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

class RsyncWeakCheck(object):
    """用于检测Rsync弱口令和弱验证 beta0.1 @Nearg1e"""

    # '.'
    _list_request = hex2str('''
    0a
    ''')

    # '@RSYNCD: 29\n'
    _hello_request = '@RSYNCD: 31\n'

    def __init__(self, host='', port=0):
        super(RsyncWeakCheck, self).__init__()
        self.host = host
        self.port = port
        self.timeout = TIME_OUT
        self.sock = None

    def _rsync_init(self):
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(self.timeout)
        sock.connect((self.host,self.port))
        sock.send(self._hello_request)
        res = sock.recv(1024)
        self.sock = sock
        return res

    def is_path_not_auth(self, path_name = ''):
        '''\
        验证某一目录是否可以被未授权访问
        >>> result = is_path_not_auth('nearg1e')
        0 # 无需登录可未授权访问
        1 # 需要密码信息进行登录
        -1 # 出现了rsync的error信息无法读取
        raisee ReqNoUnderstandError # 出现了本喵=0v0=无法预料的错误
        '''
        self._rsync_init()
        payload = path_name + '\n'
        self.sock.send(payload)
        result = self.sock.recv(1024)
        if result == '\n':
            result = self.sock.recv(1024)
        if result.startswith('@RSYNCD: OK'):
            return 0
        if result.startswith('@RSYNCD: AUTHREQD'):
            return 1
        if '@ERROR: chdir failed' in result:
            return -1
        else:
            return -1

    def get_all_pathname(self):
        self._rsync_init()
        self.sock.send(self._list_request)
        time.sleep(0.5)
        result = self.sock.recv(1024)
        if result:
            for path_name in re.split('\n', result):
                if path_name and not path_name.startswith('@RSYNCD: '):
                    yield path_name.split('\t')[0].strip()

    def _get_ver_num(self, ver_string=''):
        if ver_string:
            ver_num = ver_num_com.match(ver_string).group(1)
            if ver_num.isdigit():
                return int(ver_num)
            else: return 0
        else:
            return 0

def exploit(ip):
    port = PORT
    try:
        not_unauth_list = []
        rwc = RsyncWeakCheck(ip,int(port))
        for path_name in rwc.get_all_pathname():
            ret = rwc.is_path_not_auth(path_name)
            if ret == 0:
                not_unauth_list.append(path_name)
            elif ret == 1:
                pass
        if not_unauth_list:
            return '%s:%s >>>> 存在rsync未授权访问漏洞:%s'%(ip,port,','.join(not_unauth_list))
    except Exception, e:
        logging.error(ip+' '+str(e))
        pass