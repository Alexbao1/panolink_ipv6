# Panolink 网络拓扑探测工具

这个仓库包含了 Panolink 网络拓扑探测工具的 IPv4 和 IPv6 两个版本，用于网络探测和拓扑分析。

## 环境要求

- Ubuntu/CentOS 或其他 Linux 发行版
- Anaconda3 或 Miniconda3
- Docker
- 足够的存储空间存放探测结果

## 快速开始

### 1. 安装 Anaconda

如果您尚未安装 Anaconda，请先从[官方网站](https://www.anaconda.com/products/distribution)下载并安装。

### 2. 设置 Conda 环境

将本仓库中的两个环境文件夹复制到您的 Anaconda 环境目录中：

```bash
# 通常环境目录位于以下路径之一
# ~/anaconda3/envs/ 或 /opt/anaconda3/envs/

# 复制环境文件夹
cp -r panolink_noAS ~/anaconda3/envs/
cp -r panolink_noAS_ipv6 ~/anaconda3/envs/
```

### 3. 安装并运行 ClickHouse 数据库

Panolink 使用 ClickHouse 数据库存储探测结果：

```bash
# 安装 Docker（如果尚未安装）
sudo apt-get update
sudo apt-get install docker.io

# 拉取并运行 ClickHouse 容器
docker run --rm -d -p 8123:8123 clickhouse/clickhouse-server:22.6
```

### 4. 运行探测工具

根据您的需求选择 IPv4 或 IPv6 版本：

#### IPv6版本
```bash
# 激活环境
conda activate panolink_noAS_ipv6

# 运行探测（示例）
python panolink_noAS_ipv6.py --target_prefix 240e::/20 --rate 100000 --max_next_hop 200
```

#### IPv4版本
```bash
# 激活环境
conda activate panolink_noAS

# 运行探测（示例）
python panolink_noAS.py --target_prefix 183.0.0.0/8 --rate 100000
```


## 参数说明

### 共用参数
- --target_prefix: 要探测的目标网段
- --rate: 探测发包速率（包/秒）

### IPv6 版本独有参数
- --max_next_hop: 设定探测到的路由器下有下一跳的最大值，超出部分不纳入探测权重计算

## 结果获取

### 运行简报

探测完成后，简报将生成在 result/tight_output或result/ipv6/tight_output中。简报包含一个 UUID，用于标识本次探测任务。

### 数据库结果

探测出的链路结果保存在 ClickHouse 数据库中的 links__{uuid} 表格中，其中 {uuid} 与简报中的 UUID 一致。

您可以使用以下方式查询探测到的链路数量：
```bash
# 使用 clickhouse-client 查询
docker exec -it <container_id> clickhouse-client --query "SELECT count(DISTINCT near_addr, far_addr) FROM links__{uuid}"
```

## 注意事项

- 确保运行环境有足够的权限发送探测包（可能需要 root 权限）
- 大规模探测可能会产生大量数据，请确保有足够的磁盘空间
- 探测操作应遵循当地法律法规和网络使用政策
- 数据库容器停止后数据将丢失，如需持久化存储请添加 Docker 卷参数
