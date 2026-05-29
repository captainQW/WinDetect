# WinDiag Pro v5.0 — Windows 安全检测 & 系统诊断

基于 **Golang 后端 + Vue 3 前端** 实现的 Windows 安全检测与系统诊断工具，
对应需求文档 `WinDiag-Pro-v50-Windows-.html` 的全部功能模块。

后端采集**真实**的 Windows 系统数据（通过 gopsutil + PowerShell/CIM/WMI），
前端以单页应用方式提供仪表盘、安全发现、诊断分析、检查清单与报告导出。

## 功能模块

### 🔒 安全检测（8 个模块）
| 模块 | 检测内容 | 数据来源 |
|------|----------|----------|
| 🧱 防火墙 | 三个配置文件是否启用 | `Get-NetFirewallProfile` |
| 🛡️ Defender 防病毒 | 引擎/实时保护/病毒库存龄/篡改防护 | `Get-MpComputerStatus` |
| 🔄 系统更新 | 最近补丁、更新服务启动类型 | `Get-HotFix`, `Get-Service wuauserv` |
| 👤 账户安全 | 内置管理员/来宾账户、空密码账户 | `Get-LocalUser` |
| 🌐 网络安全 | 高危监听端口 (23/21/445/3389/5900 等) | `Get-NetTCPConnection` |
| 🚀 启动项 | 注册表自启动项、临时目录可疑项 | `HKLM/HKCU ...\Run` |
| 🔐 用户账户控制 | UAC (EnableLUA) 与提权提示级别 | 注册表 Policies\System |
| 📁 共享与远程 | 非管理性网络共享 | `Get-SmbShare` |

安全评分：满分 100，按发现严重程度扣分（严重 -20 / 高 -12 / 中 -6 / 低 -2）。

### 🔬 系统诊断
- 实时指标：CPU / 内存 / 磁盘 / 网络（gopsutil 采样）
- 性能计数器摘要、I/O 与网络摘要
- CPU / 内存 / 磁盘 / 网络 专项分析页
- 进程详情（CPU/内存/IO 排序，可疑进程标记）
- 服务状态、事件日志、硬件信息、软件环境
- 系统检查清单（扫描自动勾选）

### 📄 报告导出
HTML / JSON / CSV 三种格式，包含安全发现与诊断警告。

## 目录结构
```
WinDetect/
├── backend/                     # Go 后端
│   ├── cmd/windetect/main.go    # 入口，HTTP 服务
│   └── internal/
│       ├── api/                 # HTTP 路由与处理器
│       ├── collector/           # 数据采集 (诊断 + 安全)
│       ├── models/              # 数据结构
│       ├── report/              # 报告生成 (HTML/CSV/JSON)
│       └── winutil/             # PowerShell 调用封装
└── frontend/                    # Vue 3 + Vite 前端
    └── src/
        ├── components/          # 复用组件
        ├── views/               # 各功能页面
        ├── api.js               # 后端 API 客户端
        ├── store.js             # 全局响应式状态
        └── App.vue              # 布局与导航
```

## 运行方式

### 1. 启动后端（默认 127.0.0.1:8765）
```cmd
cd backend
go run ./cmd/windetect
```
> 部分检测项（防火墙、Defender、本地用户等）需要**管理员权限**才能读取完整数据。
> 建议以管理员身份运行终端再启动后端。

### 2. 启动前端开发服务器（默认 http://localhost:5173）
```cmd
cd frontend
npm install
npm run dev
```
Vite 已配置代理，将 `/api` 转发到后端 `127.0.0.1:8765`。

### 3. 生产构建
```cmd
cd frontend
npm run build      # 输出到 frontend/dist
```

## API 一览
| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/health` | 健康检查 |
| GET  | `/api/quick` | 轻量实时指标（用于头部仪表，可轮询） |
| GET  | `/api/security/scan` | 执行安全扫描 |
| GET  | `/api/security/last` | 上次安全扫描结果 |
| GET  | `/api/diag/scan` | 执行系统诊断 |
| GET  | `/api/diag/last` | 上次诊断结果 |
| GET  | `/api/checklist` | 检查清单定义 |
| POST | `/api/report/html` | 导出 HTML 报告 |
| POST | `/api/report/json` | 导出 JSON 报告 |
| POST | `/api/report/csv` | 导出 CSV 报告 |

## 安全说明
- 后端仅监听 `127.0.0.1`（本地回环），默认不对外暴露，也未加入鉴权。
  如需在网络中访问，请自行添加认证与访问控制。
- 工具仅做**只读检测**，不会修改系统配置；所有修复建议需用户手动执行。
- 检测结果仅供参考。

## 技术栈
- 后端：Go 1.26、`gopsutil/v4`、`pro-bing`、标准库 `net/http`
- 前端：Vue 3.5、Vite 6
