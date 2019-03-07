# README.md

用于PassiveDNSv6相关数据的分析。

## 命令说明

```
analysePDNSByMonth version: analysePDNSByMonth/1.0
Usage: analysePDNSByMonth <-source-dir sourceDir> <-mmdb mmdbFile> [-excute task] [-function function] [-date dateYearMonth] [-log-show logShow|logNotShow] [-log-file logFile|logNotFile] [-log-level logLevel] [-ips ip] [-desty-dir destFile]

Requirement:
	-source-dir sourceDir

Options:
  -beforeRes-dir string
    	已有结果目录(待合并结果文件)
  -date string
    	指定日期月份 (default "197006")
  -date-before string
    	先前日期月份 (default "197006")
  -desty-dir string
    	合并文件目录
  -domain-file string
    	域名文件
  -domains string
    	域名字符串s, ','分割
  -excute int
    	0	统计PDNS数据，进行新的分析前请自行处理临时数据，以防临时数据错误
    	1	查询MaxMind数据库地理信息
    	2	合并指定目录下的文件
    	3	查询IPv4地址
    	4	测试
    	5	什么也没做(默认) (default 5)
  -function int
    	0	统计PDNS数据:全部功能		(须指定:-excute [0])
    	1	统计PDNS数据:合并DNS记录	(须指定:-excute [0])
    	2	统计PDNS数据:去重域名		(须指定:-excute [0])
    	3	统计PDNS数据:查询IPv4地址	(须指定:-excute [0])
    	4	统计PDNS数据:合并DNS记录&V4地址	(须指定:-excute [0])
    	5	统计PDNS数据:去重TLD		(须指定:-excute [0])
    	6	统计PDNS数据:分析TLD请求次数	(须指定:-excute [0])
    	7	统计PDNS数据:获得地理信息	(须指定:-excute [0])
    	8	统计PDNS数据:根据地理去重域名	(须指定:-excute [0])
    	9	统计PDNS数据:根据地理去重IPv6	(须指定:-excute [0])
    	10	统计PDNS数据:根据地理去重SLD	(须指定:-excute [0])
    	11	统计PDNS数据:分析DNS请求次数	(须指定:-excute [0])
    	12	统计PDNS数据:分析活跃域名	(须指定:-excute [0])
    	13	统计PDNS数据:分析活跃IPv6	(须指定:-excute [0])
    	14	统计PDNS数据:分析活跃SLD		(须指定:-excute [0])
    	15	统计PDNS数据:分析SLD请求次数	(须指定:-excute [0])
    	16	什么也没做(默认) (default 16)
  -ip-file string
    	ip文件
  -ips string
    	ip地址字符串s, ','分割
  -log-file
    	log记录到日志文件(默认记录)
    	-log-file=false	log不记录到日志文件 (default true)
  -log-level int
    	0	日志等级：极简单
    	1	日志等级：简单
    	2	日志等级：一般
    	3	日志等级：详细
    	4	日志等级：极详细 (default 2)
  -log-show
    	log输出到控制台(默认输出)
    	-log-show=false	log不输出到控制台 (default true)
  -mmdb string
    	mmdb数据库路径
  -source-dir string
    	源目录(必须指定)
  -test-file string
    	测试文件路径
  -threads int
    	ZDNS查询IPv4并发数 (default 1000)
  -topn int
    	topN显示条数 (default 50)
  -zdns string
    	zdns可执行文件路径

Example:
	analysePDNSByMonth -source-dir source-dir -mmdb -zdns zdns -beforeRes-dir before-dir -date 201902 -date-before 201901 -excute 0 -function 0	分析V46地理的全部数据
```

