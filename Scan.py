#!/usr/bin/env python
# coding:utf-8
#
#针对ip快速、易用的扫描框架
# __author__="Jaqen"
#

import lib.requests as requests
import lib.masscan as masscan
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
import ssl
from lib.termcolor import colored
from bs4 import BeautifulSoup
from OpenSSL import crypto
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST, OUTPUT_FILE
)
reload(sys)
sys.setdefaultencoding('utf-8')
requests.packages.urllib3.disable_warnings()
Lock = threading.Lock()
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
            port_type = port[0]
            banner = port[1]
            port = int(port[2])
            self.ports.append(port)
            if banner:
                output('OPEN %s:%s >>>> %s'%(self.ip,port,banner.rstrip('\n')),attrs=['bold'])
                self.Reslut.append('%s >>>> %s'%(port,banner.rstrip('\n')))
            else:
                output('OPEN %s:%s >>>> %s'%(self.ip,port,port_type),attrs=['bold'])
                self.Reslut.append('%s >>>> %s'%(port,port_type.rstrip('\n')))
            try:
                url1 = "http://%s:%s"%(self.ip,port)
                url2 = "https://%s:%s"%(self.ip,port)
                httpTitle = self.getTitle(url1)
                httpsTitle = self.getTitle(url2)

                if httpTitle and httpTitle != "400 The plain HTTP request was sent to HTTPS port":
                    domain = url1
                    title = httpTitle
                    output("WEB %s >>>> %s"%(domain,title),'green')
                    self.Reslut.append('OPEN %s >>>> %s|%s'%(port,domain,title.encode('utf-8')))
                    self.domain.append(domain)
                if httpsTitle:
                    domain = url2
                    title = httpsTitle
                    try:
                        raw_cert = ssl.get_server_certificate((str(ip), str(port)))
                        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, raw_cert)
                        cert_domain = x509.get_subject().CN
                        output("WEB %s >>>> %s(%s)" % (domain, title, cert_domain), 'green')
                    except socket.error, e:
                        logging.error(e)
                        output("WEB %s >>>> %s" % (domain, title), 'green')
                    self.Reslut.append('OPEN %s >>>> %s|%s'%(port,domain,title.encode('utf-8')))
                    self.domain.append(domain)
            except socket.error,e:
                #logging.error(e)
                pass
            for plugin in imported_plugins:
                setattr(plugin, "Domain", self.domain)
                setattr(plugin, "TIME_OUT", TIME_OUT)
                setattr(plugin,"PORT",port)
                RETURN = plugin.exploit(self.ip)
                logging.error(str(plugin)+self.ip+":"+str(port)+"进行中")
                if RETURN and type(RETURN)==list:
                    for i in RETURN:
                        self.Reslut.append(i)
                        output(i,'red',attrs=['bold'])
                elif RETURN and type(RETURN)==str:
                    self.Reslut.append(RETURN)
                    output(RETURN,'red',attrs=['bold'])
                else:
                    logging.error(RETURN)

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
    parser.add_argument('-P', metavar='PLUGIN SELECT', type=str, default='None',
        help='select which plugin you want by -P scriptname,scriptname , default use None')
    parser.add_argument('-p', metavar='SCANPORT', type=str, default='0-65535',
        help='select ports you want to scan, default use 0-65535,')
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
        if args.P != 'all':
            select_plugins = args.P
            if ',' in select_plugins:
                select_plugins = select_plugins.replace(' ','').replace('\'','')
                script_plugin = select_plugins.split(',')
            else:
                if select_plugins != 'None':
                    script_plugin = []
                    script_plugin.append(select_plugins)
                else:
                    script_plugin = []
        if script_plugin:
            for plugin_name in script_plugin:
                try:
                    imported_plugin = __import__(plugin_name)
                    imported_plugins.append(imported_plugin)
                except Exception, e:
                    logging.error(e)
                    output('%s >>>> Unknow Plugin'%plugin_name, 'red')
                    print '\n[*] shutting down at %s\n'%time.strftime('%H:%M:%S',time.localtime(time.time()))
                    return
        try:
            mas = masscan.PortScanner()
        except masscan.PortScannerError:
            output('Please Install Masscan', 'red')
            return
        except:
            output("Start Masscan Error", 'red')
            return

        output('SET TIME_OUT=%d THREAD_COUNT=%d Masscan_version=%s PLUGIN_COUNT=%d'%(args.T,args.t,mas.masscan_version,len(list(script_plugin))),'green')
        for ip in get_ip_list(args.i):
            output('Starting scan target:%s'%ip, 'green')
            ResultOutput[ip] = []
            port_queue = Queue.Queue()
            try:
                mas.scan(ip, ports=args.p, arguments='--rate=2000 -sS --randomize-hosts --banners -Pn --wait '+str(TIME_OUT))#rate根据实际网络情况调整
            except Exception,e:
                logging.error(e)
                logging.error('请确认libpcap-devel、libcap是否安装。')
                output('Complete scan target:%s'%ip, 'green')
                continue
            result = mas.scan_result['scan'][ip]
            if result.has_key('tcp'):
                for tcp_port in  result['tcp']:
                    try:
                        if result['tcp'][tcp_port]['services'][0].has_key('name'):
                            banner = result['tcp'][tcp_port]['services'][0]['name']
                    except Exception,e:
                        logging.error(e)
                        banner = None
                    port_queue.put(['tcp',banner,tcp_port])
            if result.has_key('udp'):
                for udp_port in  result['udp']:
                    try:
                        if result['udp'][udp_port]['services'][0].has_key('name'):
                            banner = result['udp'][udp_port]['services'][0]['name']
                    except Exception,e:
                        logging.error(e)
                        banner = None
                    port_queue.put(['udp',banner,tcp_port])
            threads = []
            for i in xrange(THREAD_COUNT):
                scan_threads=Scan(ip,port_queue)
                scan_threads.setDaemon(True)
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
