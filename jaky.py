# -*- encoding: utf-8 -*-
#/usr/bin/python3
#author:Jaky
#Prompt before use:----pip install nmap
#端口\端口服务\指纹\子域名\备案查询\IP历史解析
import nmap,sys,re,json,requests

def callback_result(host, scan_result):
    Port_range=re.findall("services\".*\"}}, \"scanstats\"",json.dumps(scan_result))#.replace("}}, \"scanstats\"\'","")
    #print (len(a))
    for x in Port_range:
        print ("Scan port range:"+x.strip("}}, \"scanstats\"").strip("ervices\": \""))
    Port_statere=re.findall("user-set\"},.*",json.dumps(scan_result))
    #print (Port_statere)
    
#筛选出开放的端口 
    for State_filtering in Port_statere:
        port=re.findall(".{9}.state.{8}",State_filtering)
        Open_port=re.findall("\d+",str(port).replace("\": {\"state\": \"open\'","").replace("[\' {\"",""))
        print ("开放的端口:","\n",Open_port)
        print ("------------------------------------------------------------------------------------------")
        
#筛选出端口开放的服务
    for Open_service in Port_statere:
        server=re.findall("name.{10}",Open_service)
        x=str(server).replace("\'name\": \"","")
        print ("开放的端口服务:","\n",x)
        print ("------------------------------------------------------------------------------------------")
    #print ("Test weak password ing...")
    #url="http://whatweb.bugscaner.com/what.go"
    try:
#域名解析历史
        history='https://site.ip138.com/'+sys.argv[1]
        Domain_history=requests.get (history,headers={ 'User-Agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)' }).text
        print("域名历史解析结果:")
        print (str(re.findall("\d\d\d\d-\d\d-\d\d-----\d\d\d\d-\d\d-\d\d|target=\"_blank\">.*",str(str(re.findall("<span class=\"date\">.*\n.*",Domain_history)).replace("\'<span class=\"date\">","").replace(", ","\n").replace("[","").replace("]","")))).replace("target=\"_blank\">","").replace("</a>\'","").replace(", ","\n").replace("\'","").replace("</a>\\",""))
        print ("------------------------------------------------------------------------------------------")
    
 #指纹识别   
        headers={
        'Host': 'whatweb.bugscaner.com',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest'
        }
        data={'url':sys.argv[1],'location_capcha':'no'}
        cms=requests.post("http://whatweb.bugscaner.com/what.go",headers=headers,data=data).text
        newline=str(cms).replace(", ","\n").replace("{","").replace("}","").replace("\"status\": 99","-------------------------------------")#去除杂项
        print("指纹识别结果:")
        print (newline.encode('utf-8').decode('unicode_escape'))
        print ("------------------------------------------------------------------------------------------")
#旁站搜索
        Remove_prefix=re.findall("[a-zA-Z-]+.com|[a-zA-Z-]+.org|[a-zA-Z-]+.cn",sys.argv[1])
        url="https://domains.yougetsignal.com/domains.php"
        next_site=requests.post(url,headers={"User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"},data={"remoteAddress":str(Remove_prefix).replace("[\'","").replace("\']","")}).text
        print ("旁站搜索结果:")
        print (str(re.findall("domainArray.*",next_site)).replace("\", \"\"], [\"","\n").replace("\", \"\"]]}\']","").replace("[\'domainArray\":[[\"",""))
        print ("------------------------------------------------------------------------------------------")
    
#子域名搜索  
    #x='https://site.ip138.com/'+Remove_prefix+'/domain.htm'
        subdomain=requests.get ('https://site.ip138.com/'+str(Remove_prefix).replace("[\'","").replace("\']","")+'/domain.htm',headers={ 'User-Agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)' }).text
        print ("子域名搜索结果:")
        print ((str(re.findall("target=\"_blank\">.[^\s]*",str(re.findall("target=\"_blank\">.*",str(re.findall("<a href=.*</a></p>",subdomain)))))).replace("target=\"_blank\">","").replace("</a></p>","").replace("\\\\\\\',\', ","\n").replace("\']","").replace("[","").replace("\\\\\\\\","")))
        print ("------------------------------------------------------------------------------------------")

#备案号查询

        beian=requests.get ('https://site.ip138.com/'+str(Remove_prefix).replace("[\'","").replace("\']","")+'/beian.htm',headers={ 'User-Agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)' }).text
        print("备案号查询结果:")
        print (str(re.findall("target=\"_blank\">.*",str(re.findall("IC.*</a>",beian)))).replace("[\'target=\"_blank\">","").replace("</a>\\']\']",""))
        print ("------------------------------------------------------------------------------------------")
    except Exception as e:
        print (e)


# 异步Scanner
nm = nmap.PortScannerAsync()
try:
    nm.scan(sys.argv[1], ports=sys.argv[2], arguments='-Pn',callback=callback_result)
    if "gov" and "edu" in sys.argv[1]:
        print ("FBI warning:please don't scan gov/edu maliciously!!!")
    else:
# 以下是必须写的，否则你会看到一运行就退出，没有任何的结果
        while nm.still_scanning():  nm.wait(2)
except:
    info='''
  * ┏┓　  ┏┓
  *┏┛┻━━━━┛┻━━┓
  *┃　　　　  ┃ 　
  *┃　  ━　   ┃
  *┃　┳┛　┗┳　┃
  *┃　　　　  ┃
  *┃　　┻　   ┃
  *┃　　　　  ┃
  *┗━┓　　　┏━┛
  *  ┃　　　┃神兽保佑
  *  ┃　　　┃代码无BUG！
  *  ┃　　　┗━━━┓
  *  ┃　　　　  ┣┓
  *  ┃　　　　┏┛
  *  ┗┓┓┏━┳┓┏┛
  *　  ┃┫┫　┃┫┫
  *　  ┗┻┛　┗┻┛ 
  *　　　　
  '''
    print (info)
    print ("-------------------")
    print ("Use:python3 test.py domain/IP Port-range")
    print ("-------------------")
    print ("Example:python3 test.py www.baidu.com 1-1000")
    print ("-------------------")
    