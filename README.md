# TileLink Protocol Analyzer

一个用于分析和验证TileLink总线协议日志的强大工具。TileLink是RISC-V架构中使用的一种可缓存且一致性的内存总线协议。本分析器可帮助硬件设计师和系统验证工程师分析TileLink通信、检测违规、跟踪缓存状态变化，从而加速调试过程。

## 功能特点

- **全面的协议支持**：支持TileLink所有通道(A, B, C, D, E)和消息类型
- **层次化统计**：按照TileLink的操作层次(Access, Hint, Transfer)组织统计数据
- **完整的事务跟踪**：跟踪从请求到响应的完整事务流程
- **缓存一致性验证**：追踪线缓存状态变化，验证转换的正确性
- **协议违规检测**：自动检测请求-响应配对、时序顺序和通道操作的违规情况
- **可定制的输出格式**：生成详细报告，包含统计信息、违规列表和事务日志

## 安装

### 前提条件

- Python 3.6或更高版本

### 安装步骤

1. 克隆或下载此仓库
```bash
git clone https://github.com/yourusername/tilelink-analyzer.git
cd tilelink-analyzer
```

2. 使文件可执行（Linux/Mac）
```bash
chmod +x tilelink_analyzer.py
```

## 使用说明

### 基本用法

```bash
# 将分析结果输出到控制台
python tilelink_analyzer.py your_log_file.txt

# 将分析结果保存到文件
python tilelink_analyzer.py your_log_file.txt -o analysis_results.txt
```

### 命令行参数

| 参数 | 描述 |
|------|------|
| `input_file` | TileLink日志文件路径（必需） |
| `-o, --output` | 输出文件路径（可选，默认输出到控制台） |

## 输入格式

分析器支持以下TileLink日志格式：

```
<timestamp> ns <Hart>: <Channel>: <Operation> - <Parameters>
```

例如：
```
707254.18 ns Hart0: A-Channel: AcquireBlock - NtoB (0) - Grow from None to Branch size:6 source:0 addr:0x000027fe80 corrupt:0 way:0 shareable:1 user:0x079
```

## 输出格式

输出分为四个主要部分：

### 1. 事务统计

提供关于分析的TileLink流量的详细统计信息，包括：
- 总事务数和完成事务数
- 各通道操作计数
- 按操作类别分类的计数(Access, Hint, Transfer)
- 详细的消息类型计数

### 2. 协议合规性

指示日志是否符合TileLink协议规范。

### 3. 协议违规

如果检测到违规，此部分将列出所有问题，包括：
- 缺失请求/响应
- 错误的时序顺序
- 缺失参数
- 缺失确认信号
- 无效的缓存状态转换

### 4. 事务日志

以表格形式显示所有解析的TileLink事务，包括：
- 时间戳
- Hart ID
- 通道
- 操作
- 地址
- 详细参数

## TileLink协议概述

TileLink是一种内存互连协议，用于系统级芯片（SoC）设计中，特别是在基于RISC-V的系统中。它具有以下特点：

- **五个独立通道**：A（请求），B（探测），C（释放），D（响应），E（确认）
- **三种主要操作类别**：
  - Access：包含数据访问操作（Get, Put, Atomic）
  - Hint：包含预取操作（Intent）
  - Transfer：包含缓存一致性操作（Acquire, Probe, Release）
- **缓存一致性状态**：None, Branch, Trunk（类似于MESI协议的Invalid, Shared, Modified）

## 示例

### 输入日志片段
```
707254.18 ns Hart0: A-Channel: AcquireBlock - NtoB (0) - Grow from None to Branch size:6 source:0 addr:0x000027fe80 corrupt:0 way:0 shareable:1 user:0x079
707654.18 ns Hart0: D-Channel: GrantData - toT (0) - Cap to Trunk size:6 source:0 sink:1 data:0x0000000000003312000000000000000000000000000000000000000000000000 denied:0 corrupt:0 shareable:1 user:0x00
707679.18 ns Hart0: E-Channel: GrantAck - sink:1
```

### 输出片段
```
=== Transaction Statistics ===
Total transactions: 1
Complete transactions: 1

Channel operations:
A-Channel: 1
B-Channel: 0
C-Channel: 0
D-Channel: 1
E-Channel: 1

Operation Categories:
Transfer: 1
- Acquire: 1
- Probe: 0
- Release: 0

Specific Operations:
AcquireBlock: 1
...

=== Protocol Compliance ===
✅ Compliant with TileLink protocol

=== Transaction Log ===
Time (ns)      | Hart  | Channel     | Operation      | Address      | Details
----------------------------------------------------------------------------------------------------
707254.18      | Hart0 | A-Channel   | AcquireBlock   | 0x000027fe80 | NtoB (0) - Grow from None to Branch size:6 source:0 addr:0x000027...
707654.18      | Hart0 | D-Channel   | GrantData      | 0x000027fe80 | toT (0) - Cap to Trunk size:6 source:0 sink:1 data:0x0000000000...
707679.18      | Hart0 | E-Channel   | GrantAck       | -            | sink:1
```

## 定制和扩展

以下是一些可能的扩展：

1. **添加更多报告格式**：实现导出为JSON、CSV或HTML格式
2. **图形化分析**：添加生成缓存状态转换图表的功能
3. **性能分析**：添加吞吐量、延迟和总线占用率计算
4. **筛选功能**：实现按Hart、通道或地址范围过滤事务的功能
5. **波形集成**：生成与波形查看器兼容的输出

## 贡献

欢迎贡献！您可以通过以下方式参与：

1. 提交Bug报告
2. 提出新功能建议
3. 提交Pull请求修复Bug或添加新功能
