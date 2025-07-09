# Compile Tools - 技术文档

## 项目架构

### 文件结构
```
compile_tools/
├── main.py              # 主应用程序文件
├── database.py          # 数据库操作模块
├── run.py              # 启动脚本
├── requirements.txt     # Python依赖
├── USER_GUIDE.md       # 用户指南
├── TECHNICAL_DOCS.md   # 技术文档
└── compile_tools.db    # SQLite数据库文件
```

### 核心模块

#### 1. main.py - 主应用程序
- **MainWindow**: 主窗口类，管理整个应用程序界面
- **CompilationThread**: 编译线程类，处理远程编译任务
- **SshHostDialog**: SSH主机配置对话框
- **CompileProjectDialog**: 编译项目配置对话框

#### 2. database.py - 数据库模块
- SQLite数据库操作
- SSH主机配置CRUD
- 编译项目配置CRUD
- 自动数据库迁移

## 技术栈

### 核心技术
- **Python 3.9+**: 主要编程语言
- **PySide6**: GUI框架（Qt6的Python绑定）
- **Paramiko**: SSH客户端库
- **SQLite**: 轻量级数据库

### 依赖库
```
PySide6>=6.5.0    # GUI框架
paramiko>=3.0.0   # SSH客户端
```

## 数据库设计

### 表结构

#### ssh_hosts 表
```sql
CREATE TABLE ssh_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    port INTEGER DEFAULT 22,
    username TEXT NOT NULL,
    auth_method TEXT NOT NULL CHECK(auth_method IN ('password', 'key')),
    password TEXT,
    key_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### compile_projects 表
```sql
CREATE TABLE compile_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    remote_base_path TEXT NOT NULL,
    compile_commands TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 核心功能实现

### 1. SSH连接管理

#### 连接建立
```python
def get_ssh_client(self, host_id: int) -> Optional[paramiko.SSHClient]:
    # 检查现有连接
    if host_id in self._ssh_clients:
        client = self._ssh_clients[host_id]
        if client.get_transport() and client.get_transport().is_active():
            return client
    
    # 建立新连接
    host_config = database.get_ssh_host_by_id(host_id)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    # 根据认证方式连接
    if host_config["auth_method"] == "password":
        client.connect(hostname, port, username, password=password)
    else:
        client.connect(hostname, port, username, key_filename=key_path)
```

#### 连接状态监控
- 使用QTimer每5秒检查连接状态
- 在主机列表中显示实时状态指示器
- 自动清理失效连接

### 2. 远程编译

#### 多线程执行
```python
class CompilationThread(QThread):
    log_received = Signal(str)
    status_changed = Signal(str)
    compilation_finished = Signal(bool)
    
    def run(self):
        # 在远程服务器执行编译命令
        # 实时读取输出并发送信号
        # 处理编译结果
```

#### 实时日志显示
- 使用信号槽机制传递日志信息
- 非阻塞读取SSH通道输出
- 支持标准输出和错误输出合并显示

### 3. 文件管理

#### 远程文件列表
```python
def refresh_remote_artifacts(self):
    sftp = ssh_client.open_sftp()
    file_list = sftp.listdir_attr(remote_path)
    # 解析文件属性并显示在列表中
```

#### 文件下载
```python
def download_selected_artifacts(self):
    # 创建进度对话框
    progress = QProgressDialog("Downloading...", "Cancel", 0, total_files)
    
    for item in selected_items:
        if progress.wasCanceled():
            break
        # 使用SFTP下载文件
        sftp.get(remote_path, local_path)
        progress.setValue(downloaded_count)
```

## 界面设计

### UI架构
- 左侧导航栏：功能模块切换
- 右侧内容区：动态加载对应功能页面
- 模态对话框：配置编辑

### 样式设计
- 类iOS风格设计
- 圆角按钮和输入框
- 蓝色主题色 (#007AFF)
- 卡片式列表项

### 响应式布局
- 使用Qt布局管理器
- 自适应窗口大小
- 合理的间距和对齐

## 错误处理

### 异常捕获
- SSH连接异常
- 文件操作异常
- 数据库操作异常
- 网络超时异常

### 用户反馈
- 错误消息弹窗
- 状态栏信息显示
- 日志记录

## 性能优化

### 连接复用
- 维护SSH连接池
- 避免频繁建立连接
- 自动清理无效连接

### 异步操作
- 编译任务在独立线程执行
- 文件下载支持取消
- UI保持响应性

### 内存管理
- 及时关闭SSH连接
- 清理线程资源
- 限制日志缓冲区大小

## 安全考虑

### 密码存储
⚠️ **当前实现**：密码以明文存储在SQLite数据库中

### 改进建议
1. 使用系统密钥链服务
2. 实现密码加密存储
3. 支持临时密码输入
4. 添加会话超时机制

### SSH安全
- 自动接受主机密钥（开发便利性）
- 支持密钥文件认证
- 连接超时设置

## 扩展性

### 插件架构
- 模块化设计便于扩展
- 独立的数据库操作层
- 可插拔的认证方式

### 功能扩展点
1. 支持更多认证方式
2. 添加编译模板
3. 集成版本控制
4. 支持容器化编译
5. 添加编译缓存

## 部署和分发

### 打包工具
推荐使用PyInstaller：
```bash
pip install pyinstaller
pyinstaller --windowed --onefile main.py
```

### 分发注意事项
- 包含所有依赖库
- 测试不同操作系统
- 提供安装说明
- 考虑代码签名

## 开发环境

### 开发工具
- Python 3.9+
- IDE: PyCharm, VSCode等
- Git版本控制

### 调试技巧
- 使用print语句调试SSH连接
- Qt Designer设计界面
- 数据库浏览器查看数据

### 测试建议
- 测试不同SSH服务器
- 验证各种网络环境
- 测试大文件下载
- 验证异常处理
