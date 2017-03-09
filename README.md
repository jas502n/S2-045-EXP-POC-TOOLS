# S2-045-EXP-POC-TOOLS
S2-045 漏洞 POC-TOOLS 
CVE-2017-5638

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
Affected Software
Struts 2.3.5 - Struts 2.3.31, Struts 2.5 - Struts 2.5.10
Reporter
Nike Zheng <nike dot zheng at dbappsecurity dot com dot cn>
CVE Identifier
CVE-2017-5638
Problem
It is possible to perform a RCE attack with a malicious Content-Type value. If the Content-Type value isn't valid an exception is thrown which is then used to display an error message to a user.
Solution
If you are using Jakarta based file upload Multipart parser, upgrade to Apache Struts version 2.3.32 or 2.5.10.1. You can also switch to a different implementation of the Multipart parser.
Backward compatibility
No backward incompatibility issues are expected.
Workaround
Implement a Servlet filter which will validate Content-Type and throw away request with suspicious values not matching multipart/form-data.
