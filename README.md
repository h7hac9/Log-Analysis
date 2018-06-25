# Log-Analysis
日志分析工具


* 初步完成使用正则方式识别日志中常见的XSS、SQL注入等WEB 攻击类型。

* 分析步骤=> 首先将日志正则归一化处理，之后将日志传入到elasticsearch中进行分析，结果暂时打印到命令行窗口。

## 文件说明

|-venv.zip    python运行环境，解压缩后放在项目根目录，运行项目时，需要使用venv里面的python来运行
|-requirements.txt    python库管理
|-log         需要将待分析的日志文件放在log文件夹下，日志文件名格式为：域名-access-年月日.log.gz ,如：knownsec.com-access20180625.log.gz
|-logManage 
  |- logformat.ini  日志归一化配置文件，可以自定义归一化配置，具体编写规范，参照.ini文件编写规范
|-config
  |- config.ini     报警规则配置文件，可以在原有的大类中编辑rules规则，暂时不支持添加新的大类
  |- task.ini       运行日志分析时产生的.ini文件，每次结束分析任务后，需要手动将其删除
