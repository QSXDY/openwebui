# 数据库迁移指南

本指南介绍了如何使用新的数据库结构，包括微信和手机号绑定功能。

## 🚀 新功能特性

### 1. 多种登录方式支持
- **邮箱登录** - 传统的邮箱密码登录
- **手机号登录** - 手机号 + 短信验证码登录  
- **微信登录** - 微信公众号关注登录

### 2. 账号绑定功能
- 不同登录方式之间可以互相绑定
- 支持一个用户使用多种方式登录
- 灵活的绑定状态管理

### 3. 数据库结构优化
- 新增 `user_bindings` 表管理绑定关系
- 扩展 `auth` 表支持多种认证方式
- 扩展 `user` 表支持绑定信息

## 📊 数据库表结构

### auth 表 (认证表)
```sql
CREATE TABLE auth (
    id VARCHAR PRIMARY KEY,
    email VARCHAR,
    password TEXT,
    active BOOLEAN,
    -- 新增字段
    login_type VARCHAR(20) DEFAULT 'email',  -- email, phone, wechat
    external_id VARCHAR,                     -- 外部系统ID
    phone_number VARCHAR(20),                -- 手机号
    wechat_openid VARCHAR,                   -- 微信openid
    wechat_unionid VARCHAR,                  -- 微信unionid
    auth_metadata JSON                       -- 认证元数据
);
```

### user 表 (用户表)
```sql
CREATE TABLE user (
    id VARCHAR PRIMARY KEY,
    name VARCHAR,
    email VARCHAR,
    role VARCHAR,
    profile_image_url TEXT,
    -- 原有字段...
    -- 新增字段
    primary_login_type VARCHAR(20) DEFAULT 'email',
    available_login_types VARCHAR,           -- 可用登录方式，逗号分隔
    phone_number VARCHAR(20),                -- 绑定的手机号
    wechat_openid VARCHAR,                   -- 绑定的微信openid
    wechat_nickname VARCHAR,                 -- 微信昵称
    binding_status JSON                      -- 绑定状态
);
```

### user_bindings 表 (绑定关系表)
```sql
CREATE TABLE user_bindings (
    id VARCHAR PRIMARY KEY,
    primary_user_id VARCHAR NOT NULL,       -- 主用户ID
    bound_user_id VARCHAR NOT NULL,         -- 绑定的用户ID
    primary_login_type VARCHAR(20) NOT NULL,
    bound_login_type VARCHAR(20) NOT NULL,
    binding_status VARCHAR(20) DEFAULT 'active',
    binding_data JSON,
    created_at BIGINT,
    updated_at BIGINT,
    UNIQUE(primary_user_id, bound_user_id)
);
```

## 🛠️ 迁移方法

### 方法一：增量迁移（现有数据库）
如果你已经有现有的数据库，使用增量迁移：

```bash
cd backend/open_webui
python -m alembic upgrade head
```

这会执行 `b1a2c3d4e5f6_add_user_bindings_and_login_methods.py` 迁移文件。

### 方法二：完整初始化（新部署）
对于新部署，可以使用完整的初始化脚本（推荐）：

1. 确保没有现有数据库表
2. 复制 `z_init_complete_schema.py` 并重命名为合适的版本号
3. 运行迁移：
```bash
python -m alembic upgrade head
```

## 📱 API 接口更新

### 新增的接口

#### 1. 绑定手机号
```http
POST /api/v1/auths/bind/phone
Authorization: Bearer {token}
Content-Type: application/json

{
    "phone_number": "13800138000",
    "verification_code": "123456"
}
```

#### 2. 绑定微信
```http
POST /api/v1/auths/bind/wechat
Authorization: Bearer {token}
Content-Type: application/json

{
    "openid": "wechat_openid",
    "scene_id": "scene_value"
}
```

#### 3. 微信公众号关注登录
```http
POST /api/v1/auths/wechat/follow-login
Content-Type: application/json

{
    "openid": "wechat_openid",
    "scene_id": "scene_value"
}
```

#### 4. 检查微信关注状态
```http
GET /api/v1/auths/wechat/check/{scene_id}
```

### 更新的接口

#### 短信验证码发送
现在支持绑定类型：
```http
POST /api/v1/auths/sms/send
Content-Type: application/json

{
    "phone_number": "13800138000",
    "type": "bind"  // login, register, bind
}
```

## 🔧 配置更新

### 微信公众号配置
在配置中添加微信公众号相关设置：

```python
# 微信公众号配置
WECHAT_APP_ID = "your_app_id"
WECHAT_APP_SECRET = "your_app_secret"  
ENABLE_WECHAT_LOGIN = True
```

### 短信服务配置
```python
# 阿里云短信配置
SMS_ACCESS_KEY_ID = "your_key_id"
SMS_ACCESS_KEY_SECRET = "your_key_secret"
SMS_SIGN_NAME = "your_sign_name"
SMS_TEMPLATE_CODE = "your_template_code"
SMS_ENDPOINT = "dysmsapi.aliyuncs.com"
```

## 🚨 注意事项

### 1. 数据迁移安全
- 在生产环境迁移前，请先备份数据库
- 建议先在测试环境验证迁移脚本

### 2. 微信公众号设置
- 需要配置微信公众号的服务器URL
- 设置微信推送事件的接收接口: `/api/v1/auths/wechat/follow-event`

### 3. 绑定逻辑
- 用户可以有多种登录方式，但有一个主要登录方式
- 绑定关系通过 `user_bindings` 表管理
- 删除用户时需要清理相关的绑定关系

### 4. 索引优化
新增的索引可以提高查询性能：
- `ix_auth_login_type` - 按登录类型查询
- `ix_auth_phone_number` - 按手机号查询  
- `ix_auth_wechat_openid` - 按微信openid查询
- `ix_user_bindings_*` - 绑定关系查询

## 📞 故障排除

### 常见问题

1. **迁移失败**
   - 检查数据库连接
   - 确认权限足够
   - 查看错误日志

2. **绑定功能异常**
   - 检查短信服务配置
   - 验证微信公众号设置
   - 查看网络连接

3. **登录问题** 
   - 确认用户数据迁移正确
   - 检查绑定状态
   - 验证认证逻辑

## 🎯 最佳实践

1. **数据库备份**: 定期备份数据库，特别是在迁移前
2. **监控日志**: 关注登录和绑定相关的日志
3. **用户体验**: 为用户提供清晰的绑定指引
4. **安全考虑**: 验证码有效期、绑定次数限制等

## 📚 相关文档

- [微信公众平台开发文档](https://developers.weixin.qq.com/doc/)
- [阿里云短信服务文档](https://help.aliyun.com/product/44282.html)
- [Alembic迁移文档](https://alembic.sqlalchemy.org/) 