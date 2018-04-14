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
import random
import logging
import signal
import argparse

from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST, OUTPUT_FILE
)
requests.packages.urllib3.disable_warnings()
ip_queue = Queue.Queue()
Lock = threading.Lock()
plugin_info_list = []#插件信息列表
imported_plugins = []#已引入插件列表

#插件主程序
class Scan(threading.Thread):
    def __init__(self,ports):
        threading.Thread.__init__(self)
        self.ip_queue = ip_queue
        self.Domain = []#开放web
        self.ports = ports
    def run(self):
        while not self.ip_queue.empty():
            ip = self.ip_queue.get()
            output('Starting scan target:%s'%ip, 'green')
            if FindDomain_flag:
                self.Domain = self.FindDomain(ip)
            for plugin in imported_plugins:
                setattr(plugin, "FindDomain_flag", FindDomain_flag)
                setattr(plugin, "Domain", self.Domain)
                setattr(plugin, "TIME_OUT", TIME_OUT)
                RETURN = plugin.exploit(ip)
                if RETURN and type(RETURN)==list:
                    for i in RETURN:
                        output(i)
                elif RETURN and type(RETURN)==str:
                    output(RETURN)
            output('Complete scan target:%s'%ip, 'green')
    def FindDomain(self,ip):
        Domain = []
        if type(self.ports) == list:
            p = xrange(int(self.ports[0]),int(self.ports[1]))
        if type(self.ports) == str:
            p = self.ports.split(',')
        for port in p:
            url1 = "http://%s:%s"%(ip,port)
            url2 = "https://%s:%s"%(ip,port)
            try:
                resp = requests.get(url1, timeout=TIME_OUT, headers={"User-Agent": random.choice(USER_AGENT_LIST)})#越小效率越高，过小时准确度受影响
                flag = 1
            except:
                try:
                    resp = requests.get(url2,timeout=TIME_OUT, verify=False, headers={"User-Agent": random.choice(USER_AGENT_LIST)})
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
                    domain = url1
                if flag == 2:
                    domain = url2
                output("WEB %s >>>> %s"%(domain,title),'green')
                Domain.append(domain)
        return Domain

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

def parse_args():
    parser = argparse.ArgumentParser(prog='Scan-Framework',
                                    formatter_class=argparse.RawTextHelpFormatter,
                                    description='*针对ip快速、易用的扫描框架*',
                                    usage='Scan.py [options]')
    parser.add_argument('-i', metavar='IP', type=str, default='',
                        help='1.1 or 1.1.1 or 1.1.1.1-1.1.1.5 or ip.ini')
    parser.add_argument('-P', metavar='PLUGIN SELECT', type=str, default='all',
        help='select which plugin you want by -P scriptname,scriptname , default use all')
    parser.add_argument('--noweb', action='store_false',
                        help='select this to pass find domain and pass web plugins')
    parser.add_argument('-p', metavar='WEBPORT', type=str, default='70-16000',
        help='select ports you want to Brute force, default use 70-16000 or 80,443')
    parser.add_argument('-t', metavar='THREADS', type=int, default=100,
                        help='Num of scan threads, 100 by default')
    parser.add_argument('-T', metavar='TIMEOUT', type=int, default=5,
                        help='Num of scan timeout, 5 by default')
    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args
def start():
    script_plugin = []
    global FindDomain_flag,TIME_OUT
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
    print colored("PLUGINS: "+str(script_plugin), color='grey', on_color='on_white')
    args = parse_args()
    if args.i:

        TIME_OUT = args.T
        THREAD_COUNT = args.t
        print '\n[*] starting at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time()))
        output('SET TIME_OUT=%d THREAD_COUNT=%d'%(args.T,args.t),'green')
        for ip in get_ip_list(args.i):
            ip_queue.put(ip)
        if args.P != 'all':
            select_plugins = args.P
            select_plugins = select_plugins.replace(' ','').replace('\'','')
            script_plugin = select_plugins.split(',')
        if args.p:
            if '-' in args.p:
                ports = args.p.split('-')
            elif ',' in args.p:
                ports = args.p
        else:
            ports = [70,16000]
        FindDomain_flag = args.noweb
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
            scan_threads=Scan(ports)
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
