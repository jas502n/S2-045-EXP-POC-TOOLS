#CNVD-ID	CNVD-2017-02474
#发布时间	2017-03-07
#危害级别	高 (AV:N/AC:L/Au:N/C:C/I:C/A:C)
#影响产品	Apache struts >=2.3.5，<=2.3.31
#Apache struts >=2.5，<=2.5.10
#CVE ID	CVE-2017-5638 
#漏洞描述	Apache Struts是一款用于创建企业级Java Web应用的开源框架。 
#Apache Struts2存在S2-045远程代码执行漏洞。远程攻击者利用该漏洞可直接取得网站服务器控制权。

#漏洞类型	通用软硬件漏洞

#URL	参考链接	https://cwiki.apache.org/confluence/display/WW/S2-045
#漏洞解决方案	Apache Struts官方已在发布的新的版本中修复了该漏洞。建议使用Jakarta Multipart parser模块的用户升级到Apache Struts版本2.3.32或#2.5.10.1： 
#https://cwiki.apache.org/confluence/display/WW/S2-045

Summary
Possible Remote Code Execution when performing file upload based on Jakarta Multipart parser.
Who should read this
All Struts 2 developers and users
Impact of vulnerability
Possible RCE when performing file upload based on Jakarta Multipart parser
Maximum security rating
High
Recommendation
Upgrade to Struts 2.3.32 or Struts 2.5.10.1
Affected Software:Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10
Reporter
Nike Zheng  dot zheng at dbappsecurity dot com dot cn>
CVE Identifier  CVE-2017-5638
Problem
It is possible to perform a RCE attack with a malicious Content-Type value. If the Content-Type value isn't valid an exception is thrown which is then used to display an error message to a user.
Solution
If you are using Jakarta based file upload Multipart parser, upgrade to Apache Struts version 2.3.32 or 2.5.10.1. You can also switch to a different implementation of the Multipart parser.
Backward compatibility
No backward incompatibility issues are expected.
Workaround
Implement a Servlet filter which will validate Content-Type and throw away request with suspicious values not matching multipart/form-data.
