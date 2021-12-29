# ELong-永恒之恶龙

2021年12月9日晚上，Log4j的漏洞详情被公开了。至此，一个神洞出现了。我给这个漏洞起了一个名字：永恒之恶龙！为了甲方更好的自测是否受该漏洞的影响，为了乙方在授权的情况下更好的进行漏洞利用，本人开始研究并逐步公布此漏洞的受影响范围，因此本工具出现了。作者：[0e0w](https://github.com/0e0w)

本项目创建于2021年12月26日，最近的一次更新时间为2021年12月29日。

- [01-上层建筑](https://github.com/Goqi/ELong#01-%E4%B8%8A%E5%B1%82%E5%BB%BA%E7%AD%91)
- [02-漏洞证明](https://github.com/Goqi/ELong#02-%E6%BC%8F%E6%B4%9E%E8%AF%81%E6%98%8E)
- [03-漏洞利用](https://github.com/Goqi/ELong#03-%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8)
- [04-暴力扫描](https://github.com/Goqi/ELong#04-%E6%9A%B4%E5%8A%9B%E6%89%AB%E6%8F%8F)
- [05-被动扫描](https://github.com/Goqi/ELong#05-%E8%A2%AB%E5%8A%A8%E6%89%AB%E6%8F%8F)
- [06-代码扫描](https://github.com/Goqi/ELong#06-%E4%BB%A3%E7%A0%81%E6%89%AB%E6%8F%8F)

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
- [x] VMWare-Horizon
- [x] VMware-vCenter
- [x] VMWare-Workspace-One
- [ ] Ghidra
- [ ] Control-M
- [ ] Symantec-Advanced-Threat-Protection
- [ ] Cisco-CloudCenter-Suite

二、资产识别

- ELong.exe is
- ELong.exe is all
- ELong.exe is vmware
- ......

## 02-漏洞证明

使用此模块建议在资产识别之后进行，例如使用ELong.exe poc seeyon命令，会自动对isSeeyon.txt文件中的致远OA资产进行概念验证。使用ELong.exe poc all 会自动对存在漏洞的组件进行批量验证。

- ELong.exe poc
- ELong.exe poc all
- ELong.exe poc seeyon
- ELong.exe poc vmware

## 03-漏洞利用

本工具公开版本仅为poc验证工具，payload在程序中写死了，只可以判断是否存在漏洞，不可以获取系统权限。内部版提供exp功能，获取方式请加群反馈，提供一个组件的漏洞验证poc，将获取一键批量exp的原版程序！

## 04-暴力扫描

暴力扫描可以针对任意Java开发的网站！本程序支持1153个HTTP请求头的fuzz测试，作者利用此模块成功找到了2个尚未公开组件的RCE漏洞！批量fuzz可能会有意想不到的收获！但使用fuzz进行暴力扫描会发送超级多的恶意请求包，安全设备一定会产生告警，**此模块慎用**！使用此模块需要在当前路径创建urls.txt文件，运行程序会对urls.txt文件中的网址进行批量fuzz验证。

- ELong.exe fuzz
- ELong.exe fuzz one 默认使用Get请求fuzz，默认支持常见的65个Header。
- ELong.exe fuzz one max 使用Get请求对1153个Header进行漏洞扫描验证。
- ELong.exe fuzz one post 使用post请求进行fuzz验证。
- ELong.exe fuzz all 一次请求发送1153个Header进行漏洞验证。

## 05-被动扫描

此模块尚未开发完成。在浏览器中设置代理，然后程序会自动根据参数进行漏洞扫描验证。

- ELong.exe pass 

## 06-代码扫描

此模块尚未开发完成。此模块适用于企业自检，需要登录服务器。登录服务器之后运行ELong程序，指定扫描的路径即可进行扫描。此模块也适用于代码审计！

- ELong.exe scan
- ELong.exe scan all

![](./wx/WX.png)