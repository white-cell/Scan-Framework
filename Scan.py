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
import socket
import Queue
import time
import sys
import os
import random
import logging
import signal
import argparse

from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST, OUTPUT_FILE
)
reload(sys)
sys.setdefaultencoding('utf-8')
requests.packages.urllib3.disable_warnings()
Lock = threading.Lock()
plugin_info_list = []#插件信息列表
imported_plugins = []#已引入插件列表
ResultOutput = {}

#主程序
class Scan(threading.Thread):
    def __init__(self,ip,port_queue):
        threading.Thread.__init__(self)
        self.port_queue = port_queue
        self.ip = ip
        self.domain = []#开放web
        self.ports = []#开放的tcp端口
        self.Reslut = ResultOutput[ip]
    def run(self):
        while not self.port_queue.empty():
            port = self.port_queue.get()
            banner = ''
            try:
                socket.setdefaulttimeout(float(TIME_OUT)/4)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#只探测TCP端口
                sock.connect((str(self.ip),int(port)))
            except socket.error,e:
                #logging.error(e)
                continue
            try:
                banner = sock.recv(512)
                sock.close()
            except Exception,e:
                sock.close()
                logging.error(e)
                pass
            self.ports.append(port)
            if banner:
                output('OPEN %s:%s >>>> %s'%(self.ip,port,banner.rstrip('\n')),attrs=['bold'])
                self.Reslut.append('%s >>>> %s'%(port,banner.rstrip('\n')))
            else:
                output('OPEN %s:%s'%(self.ip,port),attrs=['bold'])
                self.Reslut.append('OPEN %s'%(port))
            try:
                url1 = "http://%s:%s"%(self.ip,port)
                url2 = "https://%s:%s"%(self.ip,port)
                httpTitle = self.getTitle(url1)
                httpsTitle = self.getTitle(url2)

                if httpTitle and httpTitle != "400 The plain HTTP request was sent to HTTPS port":
                    domain = url1
                    title = httpTitle
                    output("WEB %s >>>> %s"%(domain,title),'green')
                    self.Reslut.append('OPEN %s >>>> %s|%s'%(port,domain,title))
                    self.domain.append(domain)
                if httpsTitle:
                    domain = url2
                    title = httpsTitle
                    output("WEB %s >>>> %s"%(domain,title),'green')
                    self.Reslut.append('OPEN %s >>>> %s|%s'%(port,domain,title))
                    self.domain.append(domain)
            except socket.error,e:
                #logging.error(e)
                pass
            for plugin in imported_plugins:
                setattr(plugin, "Domain", self.domain)
                setattr(plugin, "TIME_OUT", TIME_OUT)
                setattr(plugin,"PORT",port)
                RETURN = plugin.exploit(self.ip)
                if RETURN and type(RETURN)==list:
                    for i in RETURN:
                        self.Reslut.append(i)
                        output(i,'red',attrs=['bold'])
                elif RETURN and type(RETURN)==str:
                    self.Reslut.append(RETURN)
                    output(RETURN,'red',attrs=['bold'])

    def getTitle(self,url):
        try:
            resp = requests.get(url, timeout=TIME_OUT, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
        except Exception, e:
            logging.error(url+str(e))
            return False
        if resp.status_code:
            title = '标题为空'
            try:
                resp.encoding = requests.utils.get_encodings_from_content(resp.content)
            except Exception, e:
                logging.error(e)
                resp.encoding = 'utf-8'
            try:
                soup = BeautifulSoup(resp.content,"html.parser")
                if soup.title.string:
                    title = soup.title.string
            except Exception, e:
                logging.error(e)
                title = '标题为空'
        return title
        

#转换ip格式
def get_ip_list(ip):
    ip_list = []
    try:
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
    except :
        output('[!] wrong input format', 'red')
        sys.exit(0)
    return ip_list
#标准化输出
def output(info, color='white', on_color=None, attrs=None):
    Lock.acquire()
    print colored("[%s] %s"%(time.strftime('%H:%M:%S',time.localtime(time.time())), info),color, on_color, attrs)
    Lock.release()
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
    parser.add_argument('-p', metavar='SCANPORT', type=str, default='21-16000',
        help='select ports you want to scan, default use 21-16000')
    parser.add_argument('-t', metavar='THREADS', type=int, default=100,
                        help='Num of scan threads, 100 by default')
    parser.add_argument('-T', metavar='TIMEOUT', type=int, default=3,
                        help='Num of scan timeout, 3 by default')
    if len(sys.argv) == 1:
        sys.argv.append('-h')
    args = parser.parse_args()
    return args
def start():
    script_plugin = []
    global TIME_OUT
    signal.signal(signal.SIGINT,KeyboardInterrupt)
    signal.signal(signal.SIGTERM,KeyboardInterrupt)
    logging.basicConfig(level=logging.WARNING,
                    format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s <%(message)s>',
                    filename='run.log',
                    filemode='w')
    print colored("""
 ____                    _____                                            _
/ ___|  ___ __ _ _ __   |  ___| __ __ _ _ __ ___   _____      _____  _ __| | __
\___ \ / __/ _` | '_ \  | |_ | '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
 ___) | (_| (_| | | | | |  _|| | | (_| | | | | | |  __/\ V  V / (_) | |  |   <
|____/ \___\__,_|_| |_| |_|  |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\  __author__="Jaqen"
""",'yellow')
    file_list = os.listdir(sys.path[0] + '/plugins/')
    sys.path.append(sys.path[0] + '/plugins/')
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
        with open(OUTPUT_FILE,'a') as FileOutput:
                FileOutput.write('[*] starting at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time())))
        output('SET TIME_OUT=%d THREAD_COUNT=%d'%(args.T,args.t),'green')
        if args.P != 'all':
            select_plugins = args.P
            select_plugins = select_plugins.replace(' ','').replace('\'','')
            script_plugin = select_plugins.split(',')
        if '-' in args.p:
            ports = args.p.split('-')
        elif ',' in args.p or args.p.isdigit():
            ports = args.p
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
        for ip in get_ip_list(args.i):
            output('Starting scan target:%s'%ip, 'green')
            ResultOutput[ip] = []
            port_queue = Queue.Queue()
            if type(ports) == list:
                p = xrange(int(ports[0]),int(ports[1]))
            if type(ports) == str:
                if ',' in ports:
                    p = ports.split(',')
                elif ports.isdigit():
                    p =[ports]
            for port in p:
                port_queue.put(port)
            threads = []
            for i in xrange(THREAD_COUNT):
                scan_threads=Scan(ip,port_queue)
                scan_threads.setDaemon(True)#为了响应Ctrl+C
                scan_threads.start()
                threads.append(scan_threads)
            for thread in threads:
                while 1:
                    if not thread.isAlive():
                        break
            output('Complete scan target:%s'%ip, 'green')
            with open(OUTPUT_FILE,'a') as FileOutput:
                FileOutput.write(ip+'\n')
                for i in ResultOutput[ip]:
                    FileOutput.write('|--%s\n'%i)
                FileOutput.write('\n')
        print '\n[*] shutting down at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time()))
        with open(OUTPUT_FILE,'a') as FileOutput:
                FileOutput.write('[*] shutting down at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time())))


if __name__ == '__main__':
    start()