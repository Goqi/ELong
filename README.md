# ELong-永恒之恶龙

2021年12月9日晚上，Log4j的漏洞详情被公开了。至此，一个神洞出现了。我给这个漏洞起了一个名字：永恒之恶龙！为了甲方更好的自测是否受该漏洞的影响，为了乙方在授权的情况下更好的进行漏洞利用，本人开始研究并逐步公布此漏洞的受影响范围，因此本工具出现了。作者：[0e0w](https://github.com/0e0w)

本项目创建于2021年12月26日，最近的一次更新时间为2021年12月28日。

- [01-上层建筑]()
- [02-漏洞证明]()
- [03-漏洞利用]()
- [04-暴力扫描]()
- [05-被动扫描]()
- [06-代码扫描]()

## 01-资产识别

一、受影响的资产
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
- [ ] Apache-Struts2-showcase#
- [x] Apache-Struts2
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

二、资产扫描

- ELong.exe is
- ELong.exe is all
- ELong.exe is vmware
- ......

## 02-漏洞证明

- ELong.exe poc
- ELong.exe poc all
- ELong.exe poc seeyon

## 03-漏洞利用

本工具仅为poc验证工具，只可以判断是否存在漏洞，不可以获取权限。公开版本不提供exp功能请加群反馈，提供一个组件的漏洞验证程序，将获取一键批量exp的原版程序！

## 04-暴力扫描

使用fuzz进行暴力扫描会发送超级多的恶意请求包，安全设备一定会产生告警，此功能慎用！

- ELong.exe fuzz
- ELong.exe fuzz one 默认Get请求，默认常规字典
- ELong.exe fuzz one max
- ELong.exe fuzz one post
- ELong.exe fuzz all

## 05-被动扫描

- ELong.exe pass 

## 06-代码扫描

此模块适用于企业自检，需要登录服务器。登录服务器之后运行ELong程序，指定扫描的路径即可进行扫描。此模块也适用于代码审计！该功能待实现

- ELong.exe scan
- ELong.exe scan all