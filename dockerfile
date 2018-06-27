# Version 2.1

# 基础镜像
FROM dockerlucifer/elasticsearch:v2.0.6

MAINTAINER daemonshao@gmail.com

EXPOSE 9100
EXPOSE 9200
EXPOSE 20

ENTRYPOINT ["/usr/bin/supervisord","-c","/etc/supervisor/conf.d/supervisord.conf"]
