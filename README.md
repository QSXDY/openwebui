> 该项目是社区驱动的开源 AI 平台 [Open WebUI](https://github.com/open-webui/open-webui) 的定制分支。此版本与 Open WebUI 官方团队没有任何关联，亦非由其维护。

# Open WebUI 👋

官方文档: [Open WebUI Documentation](https://docs.openwebui.com/).  
官方更新日志: [CHANGELOG.md](./CHANGELOG.md)

## 部署方式

部署后，不能直接回退到官方镜像；如需使用官方镜像，请参考此篇 [Wiki](https://github.com/U8F69/open-webui/wiki/%E9%87%8D%E6%96%B0%E4%BD%BF%E7%94%A8%E5%AE%98%E6%96%B9%E9%95%9C%E5%83%8F) 处理

部署二开版本只需要替换镜像和版本，其他的部署与官方版本没有差别，版本号请在 [Release](https://github.com/U8F69/open-webui/releases/latest) 中查看

```
ghcr.io/u8f69/open-webui:<版本号>
```

## 拓展特性

完整特性请看更新日志 [CHANGELOG_EXTRA.md](./CHANGELOG_EXTRA.md)

### 积分报表

![usage panel](./docs/usage_panel.png)

### 全局积分设置

![credit config](./docs/credit_config.png)

### 用户积分管理与充值

![user credit](./docs/user_credit.png)

### 按照 Token 或请求次数计费，并在对话 Usage 中显示扣费详情

![usage](./docs/usage.png)

### 支持注册邮箱验证

![email](./docs/sign_verify_user.png)

## 拓展配置

### 注册邮箱验证

![verify email](./docs/signup_verify.png)

请在管理端打开注册邮箱验证，配置 WebUI URL，同时配置如下环境变量

```
# 缓存
REDIS_URL=redis://:<password>@<host>:6379/0

# 邮件相关
SMTP_HOST=smtp.email.qq.com
SMTP_PORT=465
SMTP_USERNAME=example@qq.com
SMTP_PASSWORD=password
```

### 品牌/LOGO定制能力说明

本项目尊重并遵守 [Open WebUI License](https://docs.openwebui.com/license) 的品牌保护条款；我们鼓励社区用户尽量保留原有 Open WebUI 品牌，支持开源生态！

如需自定义品牌标识（如 LOGO、名称等）：

- 请务必确保您的实际部署满足 License 所要求的用户规模、授权条件等（详见 [官方说明#9](https://docs.openwebui.com/license#9-what-about-forks-can-i-start-one-and-remove-all-open-webui-mentions)）。
- 未经授权的商用或大规模去除品牌属于违规，由使用者自行承担法律风险。
- 具体自定义方法见 [docs/BRANDING.md](./docs/BRANDING.md)。

## Docker 部署

### 快速开始

使用以下命令快速启动 Open WebUI，默认使用 SQLite 数据库：

```bash
docker run -d \
  --name open-webui \
  -p 3000:8080 \
  -v open-webui:/app/backend/data \
  ghcr.io/cnqsxdy/openwebui:latest
```

### 使用特定版本

```bash
docker run -d \
  --name open-webui \
  -p 3000:8080 \
  -v open-webui:/app/backend/data \
  ghcr.io/cnqsxdy/openwebui:<版本号>
```

### 使用 MySQL 和 Redis

可以通过环境变量配置连接 MySQL 和 Redis。请根据你的实际情况修改连接字符串和密码:

```bash
docker run -d \
  --name open-webui \
  -p 3000:8080 \
  -v open-webui:/app/backend/data \
  -e DATABASE_URL="mysql+pymysql://user:password@your_mysql_host:3306/dbname" \
  -e REDIS_URL="redis://:password@your_redis_host:6379/0" \
  ghcr.io/cnqsxdy/openwebui:latest
```

请确保 `your_mysql_host` 和 `your_redis_host` 可以被 Docker 容器访问到。

## Docker Compose 部署

### 快速启动 (SQLite)

在项目根目录下执行，默认使用 SQLite 数据库：

```bash
docker compose up -d
```

### 使用 MySQL 和 Redis

修改 `docker-compose.yaml` 文件，取消 `mysql` 和 `redis` 服务的注释，并根据你的需求配置环境变量。然后执行：

```bash
docker compose up -d
```

请确保在 `.env` 文件或者直接在 `docker-compose.yaml` 中配置 `WEBUI_SECRET_KEY`。

### 主要服务说明

- `open-webui`: 主 WebUI 服务。
- `ollama`: 大模型服务。
- `mysql` (可选): MySQL 数据库服务，需取消注释并配置。
- `redis` (可选): Redis 服务，用于高级功能（如积分、邮箱验证），需取消注释并配置。

### 环境变量说明

- `WEBUI_SECRET_KEY`: WebUI 密钥，**必须设置为强密码**。
- `DATABASE_URL`: 数据库连接字符串，默认使用 SQLite (`sqlite:///app/backend/data/webui.db`)。如使用 MySQL，请修改为 `mysql+pymysql://user:password@mysql:3306/dbname` (如果MySQL服务也在同一个docker-compose网络中) 或 `mysql+pymysql://user:password@your_mysql_host:3306/dbname` (如果MySQL在外部)。
- `REDIS_URL`: Redis 连接字符串，启用积分/邮箱验证等功能时需配置。如使用 Redis 服务在同一个docker-compose网络中，请修改为 `redis://:password@redis:6379/0`。如Redis在外部，请修改为 `redis://:password@your_redis_host:6379/0`。

### 数据持久化

- `open-webui` 卷: 持久化 WebUI 数据（包括 SQLite 数据库文件）。
- `ollama` 卷: 持久化大模型数据。
- `mysql_data` 卷: 持久化 MySQL 数据（如启用）。
- `redis_data` 卷: 持久化 Redis 数据（如启用）。
