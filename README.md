# ELong-永恒之恶龙

2021年12月9日晚上，Log4j的漏洞详情被公开了。至此，一个神洞出现了。我们给这个漏洞起了一个名字：永恒之恶龙！可以利用该工具更好的自测是否受该漏洞的影响，或是在授权的情况下可以利用该工具更好的进行漏洞探测或漏洞利用。作者将持续关注并逐步公布此漏洞的影响范围。公开版获取方式请查看微信群公告。作者：[Goqi](https://github.com/Goqi)

本项目创建于2021年12月26日，最近的一次更新时间为2022年1月1日。

- [01-上层建筑](https://github.com/Goqi/ELong#01-%E4%B8%8A%E5%B1%82%E5%BB%BA%E7%AD%91)
- [02-漏洞证明](https://github.com/Goqi/ELong#02-%E6%BC%8F%E6%B4%9E%E8%AF%81%E6%98%8E)
- [03-漏洞利用](https://github.com/Goqi/ELong#03-%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8)
- [04-暴力扫描](https://github.com/Goqi/ELong#04-%E6%9A%B4%E5%8A%9B%E6%89%AB%E6%8F%8F)
- [05-代码扫描](https://github.com/Goqi/ELong#05-%E4%BB%A3%E7%A0%81%E6%89%AB%E6%8F%8F)
- [06-被动扫描](https://github.com/Goqi/ELong#06-%E8%A2%AB%E5%8A%A8%E6%89%AB%E6%8F%8F)
- [07-参考资源]()

## 01-上层建筑

一、漏洞资产
- [x] Apereo-CAS
- [x] Apache-Druid
- [ ] Apache Dubbo
- [x] Apache-Flink
- [ ] Apache Flume
- [ ] Apache-James#
- [x] Apache-JspWiki
- [ ] Apache-Kafka
- [x] Apache-OFBiz
- [x] Apache-SkyWalking
- [x] Apache-Solr
- [x] Apache-Struts2
- [ ] Apache-Struts2-showcase#
- [ ] Apache Spark
- [x] Apache Storm
- [ ] Apache Tomcat
- [ ] Logstash
- [ ] Elasticsearch#
- [x] MobileIron-User-Portal
- [ ] Redis
- [x] Seeyon
- [ ] SpringBoot#
- [ ] Spring-Boot-strater-log4j2
- [x] Unifi-Network
- [x] VMware-HCX
- [x] VMware-Horizon
- [x] VMware-NSX
- [x] VMware-vCenter
- [x] VMware-vRealize
- [x] VMware-Workspace-One
- [x] Zipkin
- [ ] Ghidra
- [ ] Control-M
- [ ] Symantec-Advanced-Threat-Protection
- [ ] Cisco-CloudCenter-Suite

二、资产识别

​	资产识别功能暂时不准备更新，资产识别可以通过[Banli](https://github.com/Goqi/Banli)这个项目实现！

- ELong.exe is
- ELong.exe is all
- ELong.exe is vmware
- ......

## 02-漏洞证明

程序目前的设计模式是只扫描不检测，通过JNDI或DNSLOG平台判断是否存在漏洞。使用此模块建议在资产识别之后进行。请创建poc.txt文件，内容为dnslog平台URL地址。使用ELong.exe poc seeyon命令，会自动对isSeeyon.txt文件中的致远OA进行漏洞验证，使用ELong.exe poc solr命令，会自动对isSolr.txt文件中的Solr资产进行漏洞验证。等。使用ELong.exe poc all 会自动对存在漏洞的组件进行批量验证。

- ELong.exe poc
- ELong.exe poc seeyon
- ELong.exe poc solr
- ELong.exe poc all

## 03-漏洞利用

本工具公开版仅为poc验证工具，payload在程序中写死了，只可以判断是否存在漏洞，不可以获取系统权限。内部版提供exp功能，暂时不对外公开。

## 04-暴力扫描

暴力扫描可以针对任意Java开发的网站！本程序支持**1153个**HTTP请求头的fuzz测试，作者利用此模块成功找到了2个尚未公开组件的RCE漏洞！批量fuzz往往会有意想不到的收获，但使用fuzz模块进行暴力扫描会发送超级多的恶意请求包，安全设备一定会产生告警，**此模块慎用**！使用此模块需要在当前路径创建urls.txt文件，运行程序会对urls.txt文件中的网址进行HTTP请求头批量fuzz验证。

- ELong.exe fuzz
- ELong.exe fuzz one 默认使用Get请求fuzz，默认支持常见的65个Header。
- ELong.exe fuzz one max 使用Get请求对1153个Header进行漏洞扫描验证。
- ELong.exe fuzz one post 使用post请求进行fuzz验证。
- ELong.exe fuzz all 一次请求发送1153个Header进行漏洞验证。

## 05-代码扫描

此模块适用于企业自检，需要登录服务器之后运行ELong程序，通过scan参数指定扫描的路径即可进行扫描，可以同时指定多个扫描路径。不建议进行根目录扫描，效率太低，无用功太多。此模块也适用于代码审计！

- ELong.exe scan 路径
- ELong.exe scan D:\web
- ./ELong scan /home/web /etc/code

## 06-被动扫描

此模块尚未开发完成。开发计划：在浏览器中设置代理，程序自动根据请求参数进行漏洞扫描验证。

- ELong.exe pass 

## 07-参考资源

- https://github.com/0e0w/HackLog4j
- https://github.com/darkarnium/Log4j-CVE-Detect

![](TEMP/wx.png)