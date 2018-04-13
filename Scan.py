#!/usr/bin/env python
# coding:utf-8
#
#针对ip快速、易用的扫描框架
# __author__="Jaqen"
#

import lib.requests as requests
from lib.termcolor import colored
from bs4 import BeautifulSoup
import threading
import Queue
import time
import sys
import json
import re
import os
import logging
import signal

from lib.config import (
    PASSWORD_DIC, THREAD_COUNT, TIME_OUT, MY_PROXY, USER_AGENT_LIST, OUTPUT_FILE
)
requests.packages.urllib3.disable_warnings()
ip_queue = Queue.Queue()
port_queue = Queue.Queue()
Lock = threading.Lock()
plugin_info_list = []#插件信息列表
imported_plugins = []#已引入插件列表

#插件主程序
class Scan(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.ip_queue = ip_queue
        self.Domain = []#开放web
    def run(self):
        while not self.ip_queue.empty():
            ip = self.ip_queue.get()
            output('Starting scan target:%s'%ip, 'green')
            if FindDomain_flag != 'n':
                self.Domain = self.Find(ip)
            for plugin in imported_plugins:
                setattr(plugin, "FindDomain_flag", FindDomain_flag)
                setattr(plugin, "Domain", self.Domain)
                RETURN = plugin.exploit(ip)
                if RETURN and type(RETURN)==list:
                    for i in RETURN:
                        output(i)
                elif RETURN and type(RETURN)==str:
                    output(RETURN)
            output('Complete scan target:%s'%ip, 'green')
    def Find(self,ip):
        threads = []
        scan_threads=[FindDomain(ip)for i in xrange(100)]
        threads.extend(scan_threads)
        [thread.start() for thread in threads]
        for thread in threads:
            thread.join()
            if thread.result():
                self.Domain.append(thread.result())
        return self.Domain
#挖掘web
class FindDomain(threading.Thread):
    def __init__(self,ip):
        threading.Thread.__init__(self)
        self.port_queue = port_queue
        self.ip = ip
        self.domain = ''
    def run(self):
        while not self.port_queue.empty():
            port = self.port_queue.get()
            url1 = "http://%s:%d"%(self.ip,port)
            url2 = "https://%s:%d"%(self.ip,port)
            try:
                resp = requests.get(url1,timeout=3)#越小效率越高，过小时准确度受影响
                flag = 1
            except:
                try:
                    resp = requests.get(url2,timeout=3, verify=False)
                    flag = 2
                except:
                    continue
            if resp.status_code:
                try:
                    resp.encoding = requests.utils.get_encodings_from_content(resp.content)
                except Exception, e:
                    logging.error(e)
                    resp.encoding = 'utf-8'
                try:
                    soup = BeautifulSoup(resp.content,"html.parser")
                    title = soup.title.string
                except Exception, e:
                    logging.error(e)
                    title = 'Null'
                if flag == 1:
                    self.domain = url1
                if flag == 2:
                    self.domain = url2
                output("WEB %s >>>> %s"%(self.domain,title),'green')
    def result(self):
        if self.domain:
            return self.domain
#转换ip格式
def get_ip_list(ip):
    ip_list = []
    iptonum = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
    numtoip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
    if '-' in ip:
        ip_range = ip.split('-')
        ip_start = long(iptonum(ip_range[0]))
        ip_end = long(iptonum(ip_range[1]))
        ip_count = ip_end - ip_start
        if ip_count >= 0 and ip_count <= 65536:
            for ip_num in range(ip_start,ip_end+1):
                ip_list.append(numtoip(ip_num))
        else:
            output('[!] wrong input format', 'red')
            sys.exit()
    elif '.ini' in ip:
        with open(ip,'r') as ip_config:
            for ip in ip_config:
                ip_list.extend(get_ip_list(ip.rstrip('\n').strip()))
    else:
        ip_split=ip.split('.')
        net = len(ip_split)
        if net == 2:
            for b in range(1,255):
                for c in range(1,255):
                    ip = "%s.%s.%d.%d"%(ip_split[0],ip_split[1],b,c)
                    ip_list.append(ip)
        elif net == 3:
            for c in range(1,255):
                ip = "%s.%s.%s.%d"%(ip_split[0],ip_split[1],ip_split[2],c)
                ip_list.append(ip)
        elif net ==4:
            ip_list.append(ip)
        else:
            output('[!] wrong input format', 'red')
            sys.exit(0)
    return ip_list
#标准化输出
def output(info, color='white', on_color=None, attrs=None):
        print colored("[%s] %s"%(time.strftime('%H:%M:%S',time.localtime(time.time())), info),color, on_color, attrs)
def KeyboardInterrupt(signum,frame):
    output('[ERROR] user quit','red')
    print '\n[*] shutting down at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time()))
    sys.exit(0)


def start():
    script_plugin = []
    global FindDomain_flag
    FindDomain_flag = 'y'#是否探测web端口标志位
    signal.signal(signal.SIGINT,KeyboardInterrupt)
    signal.signal(signal.SIGTERM,KeyboardInterrupt)
    print colored("""
 ____                    _____                                            _
/ ___|  ___ __ _ _ __   |  ___| __ __ _ _ __ ___   _____      _____  _ __| | __
\___ \ / __/ _` | '_ \  | |_ | '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
 ___) | (_| (_| | | | | |  _|| | | (_| | | | | | |  __/\ V  V / (_) | |  |   <
|____/ \___\__,_|_| |_| |_|  |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\  __author__="Jaqen"
""",'yellow')
    file_list = os.listdir(sys.path[0] + '/plugins/')
    sys.path.append(sys.path[0] + '/plugins/')
    logging.basicConfig(level=logging.WARNING,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s <%(message)s>',
                    filename='run.log',
                    filemode='w')
    for filename in file_list:
        try:
            if '.py' in filename:
                if filename.split('.')[1] == 'py' and filename.split('.')[0] != '__init__':
                    script_plugin.append(filename.split('.')[0])
        except Exception, e:
            logging.error(e)
    if len(sys.argv) == 2:
        print '\n[*] starting at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time()))
        for ip in get_ip_list(sys.argv[1]):
            ip_queue.put(ip)
        for port in xrange(70,16000):
            port_queue.put(port)

        plugins_flag = raw_input(colored("[%s] %s"%(time.strftime('%H:%M:%S',time.localtime(time.time())), 'Use all plugins? [Y/n/q] '),'green'))
        plugins_flag = plugins_flag[0:1]
        plugins_flag = plugins_flag.lower()
        if plugins_flag == 'q':
            KeyboardInterrupt(0,0)
        elif plugins_flag == 'n':
            print colored("PLUGINS: "+str(script_plugin), color='grey', on_color='on_white')
            select_plugins = raw_input(colored("[%s] %s"%(time.strftime('%H:%M:%S',time.localtime(time.time())),'Please input which plugin you want? [use , split] '),'green'))
            select_plugins = select_plugins.replace(' ','').replace('\'','')
            script_plugin = select_plugins.split(',')

        FindDomain_flag = raw_input(colored("[%s] %s"%(time.strftime('%H:%M:%S',time.localtime(time.time())),'Use find domain? [Y/n/q] '),'green'))
        FindDomain_flag = FindDomain_flag[0:1]
        FindDomain_flag = FindDomain_flag.lower()
        if FindDomain_flag == 'q':
            KeyboardInterrupt(0,0)
        for plugin_name in script_plugin:
            try:
                imported_plugin = __import__(plugin_name)
                imported_plugins.append(imported_plugin)
                plugin_info = imported_plugin.get_plugin_info()
                plugin_info['filename'] = plugin_name
                plugin_info['count'] = 0
                plugin_info_list.append(plugin_info)
            except Exception, e:
                logging.error(e)
        threads = []
        for i in xrange(THREAD_COUNT):
            scan_threads=Scan()
            scan_threads.setDaemon(True)#为了响应Ctrl+C
            threads.append(scan_threads)
            scan_threads.start()
        while 1:
         alive = False
         for i in range(THREAD_COUNT):
             alive = alive or threads[i].isAlive()#为了响应Ctrl+C不能用join
         if not alive:
             break
        print '\n[*] shutting down at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time()))
    else:
        usage()
def usage():
    print "Usage: python "+sys.argv[0]+" 1.1.1 or 1.1.1.1-1.1.1.5 or ip.ini\n"

if __name__ == '__main__':
    start()
