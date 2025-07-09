# Compile Tools - 用户使用指南

## 概述

Compile Tools 是一个桌面应用程序，用于简化开发者与远程服务器的交互，提供SSH连接管理、远程项目编译以及编译产物下载的核心功能。

## 安装和运行

### 系统要求
- Python 3.9 或更高版本
- Windows/macOS/Linux 操作系统

### 安装步骤

1. **安装依赖**
   ```bash
   pip install -r requirements.txt
   ```

2. **运行应用程序**
   ```bash
   python run.py
   ```
   或者直接运行：
   ```bash
   python main.py
   ```

## 功能使用指南

### 1. SSH主机管理

#### 添加新主机
1. 点击左侧导航栏的"Host Management"
2. 点击"Add New Host"按钮
3. 填写主机信息：
   - **Display Name**: 主机的显示名称
   - **Hostname/IP**: 服务器地址
   - **Port**: SSH端口（默认22）
   - **Username**: 登录用户名
   - **Auth Method**: 选择认证方式
     - **Password**: 密码认证
     - **Key File**: 密钥文件认证
4. 点击"Test Connection"测试连接
5. 点击"Save"保存配置

#### 编辑和删除主机
- 选择主机后点击"Edit Selected"进行编辑
- 选择主机后点击"Delete Selected"删除主机
- 主机列表中的状态指示器：
  - 🟢 已连接
  - 🔴 未连接

### 2. 编译项目管理

#### 添加新项目
1. 点击左侧导航栏的"Project Configuration"
2. 点击"Add New Project"按钮
3. 填写项目信息：
   - **Project Name**: 项目名称（唯一标识）
   - **Remote Project Root Path**: 远程项目根目录
   - **Compile Commands**: 编译命令（支持多行）
   - **Compiled Artifacts Path**: 编译产物目录
4. 点击"Save"保存配置

#### 编辑和删除项目
- 选择项目后点击"Edit Selected Project"进行编辑
- 选择项目后点击"Delete Selected Project"删除项目

### 3. 远程编译和文件下载

#### 执行编译
1. 点击左侧导航栏的"Compile & Run"
2. 选择要编译的项目和目标主机
3. 点击"Test Connection"测试连接（可选）
4. 点击"Start Compilation"开始编译
5. 实时查看编译日志
6. 如需中断，点击"Interrupt"按钮

#### 下载编译产物
1. 编译成功后，产物列表会自动刷新
2. 或手动点击"Refresh Artifacts"刷新列表
3. 选择要下载的文件（支持多选）
4. 点击"Download Selected"
5. 选择本地保存目录
6. 查看下载进度

## 功能特性

### ✅ 已实现功能
- SSH连接管理（密码和密钥认证）
- 连接状态实时显示
- 编译项目配置管理
- 远程编译执行
- 实时编译日志显示
- 编译中断功能
- 远程文件列表获取
- 文件下载（带进度条）
- 配置数据持久化
- 类iOS风格用户界面

### 🔧 技术特性
- 多线程编译执行
- 自动数据库迁移
- 错误处理和用户友好提示
- 连接状态监控
- 进度显示

## 故障排除

### 常见问题

1. **连接失败**
   - 检查网络连接
   - 验证主机地址和端口
   - 确认用户名和密码/密钥文件正确

2. **编译失败**
   - 检查编译命令是否正确
   - 确认远程项目路径存在
   - 查看编译日志了解具体错误

3. **下载失败**
   - 确认产物路径配置正确
   - 检查文件权限
   - 确保有足够的本地存储空间

### 日志和调试
- 编译日志会实时显示在界面中
- 可以点击"Clear Log"清空日志
- 错误信息会通过弹窗显示

## 数据存储

应用程序使用SQLite数据库存储配置信息：
- **Windows**: `%APPDATA%\CompileTools\compile_tools.db`
- **macOS**: `~/Library/Application Support/CompileTools/compile_tools.db`
- **Linux**: `~/.local/share/CompileTools/compile_tools.db`

## 安全注意事项

⚠️ **重要提醒**：
- 密码以明文形式存储在本地数据库中
- 生产环境建议使用密钥认证
- 定期更新SSH密钥
- 不要在不安全的环境中使用

## 技术支持

如遇问题，请检查：
1. Python版本是否符合要求
2. 依赖包是否正确安装
3. 网络连接是否正常
4. SSH服务器配置是否正确
