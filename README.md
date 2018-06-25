# Log-Analysis
日志分析工具


* 初步完成使用正则方式识别日志中常见的XSS、SQL注入等WEB 攻击类型。

* 分析步骤=> 首先将日志正则归一化处理，之后将日志传入到elasticsearch中进行分析，结果暂时打印到命令行窗口。

## 文件说明

|-venv.zip    python运行环境，解压缩后放在项目根目录，运行项目时，需要使用venv里面的python来运行<br/>
|-requirements.txt    python库管理<br/>
|-log         需要将待分析的日志文件放在log文件夹下，日志文件名格式为：域名-access-年月日.log.gz ,如：knownsec.com-access20180625.log.gz<br/>
|-logManage<br/> 
&nbsp;&nbsp;|-&nbsp;logformat.ini  日志归一化配置文件，可以自定义归一化配置，具体编写规范，参照.ini文件编写规范<br/>
|-config<br/>
&nbsp;&nbsp;|-&nbsp;config.ini     报警规则配置文件，可以在原有的大类中编辑rules规则，暂时不支持添加新的大类<br/>
&nbsp;&nbsp;|-&nbsp;task.ini       运行日志分析时产生的.ini文件，每次结束分析任务后，需要手动将其删除<br/>

## Docker镜像

该项目主要架构是将日志文件经过归一化处理之后存放到Elasticsearch中，之后使用Elasticsearch的API对日志进行分析。<br>
本项目配套的Docker下方法为：
```shell
docker pull dockerlucifer/elasticsearch:v1.0.0

#推荐使用DaoCloud加速器来下载，链接：https://www.daocloud.io/mirror#accelerator-doc
```
下载完成docker镜像之后使用images命令浏览docker image列表：
```shell
root@daemonshao:~# docker images
REPOSITORY                    TAG                 IMAGE ID            CREATED             SIZE
dockerlucifer/elasticsearch   v1.0.0              fa1e6efc7c76        2 hours ago         869MB
```
使用docker image创建docker 容器：
```shell
docker run -p 9100:9100 -p 9200:9200 --privileged -it fa1e6efc7c76 /bin/bash

#命令格式：docker run -it 【IMAGE ID】 /bin/bash
```

### Docker 容器配置
#### 启动elasticsearch 服务
```shell
#注意：elasticsearch会将docker容器中的9100、9200端口映射到宿主机，所以确保自己的主机9100以及9200端口没有被占用
root@59431ac10dd6:~# vim /etc/sysctl.conf

--------sysctl.conf-------------
vm.max_map_count=262144  # 添加一行配置

root@59431ac10dd6:~# sysctl -p

root@59431ac10dd6:~# cd /opt/elasticsearch-6.2.4/
root@59431ac10dd6:/opt/elasticsearch-6.2.4# ls      
LICENSE.txt  NOTICE.txt  README.textile  bin  config  lib  logs  modules  nohup.out  plugins
root@59431ac10dd6:/opt/elasticsearch-6.2.4# su elastic
$ nohup bin/elasticsearch &
```
验证：访问http://【宿主机IP】:9200/
![9200]('readme/9200.png')

#### 启动elastic-head
```shell
root@59431ac10dd6:/opt# cd elasticsearch-head-master/
root@59431ac10dd6:/opt/elasticsearch-head-master# source /etc/profile
root@59431ac10dd6:/opt/elasticsearch-head-master# nohup grunt server &
```
验证：访问http://【宿主机IP】:9100/
![9100]('readme/9100.png')
