# 系统升级总结

## 🎯 主要功能升级

### 1. 微信登录方式改进
- **从微信扫码登录改为微信公众号关注登录**
- 用户需要关注公众号才能完成登录
- 更好的用户留存和粉丝增长

### 2. 多种登录方式支持
- **邮箱登录** - 原有的邮箱密码登录方式
- **手机号登录** - 手机号 + 短信验证码登录
- **微信公众号登录** - 关注公众号后自动登录

### 3. 账号绑定功能
- 支持不同登录方式之间的绑定
- 微信登录后可以绑定手机号
- 手机号登录后可以绑定微信
- 一个账号支持多种登录方式

## 🛠️ 技术实现

### 后端修改

#### 1. 数据库结构扩展
- **新增表**: `user_bindings` - 管理用户绑定关系
- **扩展 auth 表**: 添加多种登录方式支持字段
- **扩展 user 表**: 添加绑定状态和信息字段
- **创建完整迁移脚本**: `b1a2c3d4e5f6_add_user_bindings_and_login_methods.py`

#### 2. 模型层更新
- 更新 `AuthModel` 和 `UserModel` 支持新字段
- 新增 `UserBindingModel` 管理绑定关系
- 新增 `UserBindingsTable` 类处理绑定逻辑

#### 3. API接口扩展
```python
# 新增的API接口
POST /auths/bind/phone          # 绑定手机号
POST /auths/bind/wechat         # 绑定微信
POST /auths/wechat/follow-login # 微信公众号关注登录
GET  /auths/wechat/check/{scene_id} # 检查关注状态
POST /auths/wechat/follow-event # 微信关注事件回调

# 更新的接口
POST /auths/sms/send           # 支持绑定类型验证码
```

#### 4. 微信服务重构
- `WeChatService` → `WeChatFollowService`
- 从网页授权改为公众号带参数二维码
- 支持关注事件处理和状态检查

### 前端修改

#### 1. 登录界面更新
- 更新微信登录UI提示文案
- 添加绑定手机号弹窗组件
- 优化用户体验流程

#### 2. API调用更新
```javascript
// 新增的前端API
weChatFollowLogin()    // 微信公众号关注登录
checkWeChatFollowStatus() // 检查关注状态
bindPhoneNumber()      // 绑定手机号
bindWeChat()          // 绑定微信
```

#### 3. 登录流程优化
- 微信登录后检查是否需要绑定手机号
- 显示绑定提示和操作界面
- 支持跳过绑定选项

## 📁 文件变更清单

### 新增文件
- `backend/open_webui/migrations/versions/b1a2c3d4e5f6_add_user_bindings_and_login_methods.py`
- `backend/DATABASE_MIGRATION_GUIDE.md`
- `backend/CHANGES_SUMMARY.md`

### 修改文件
- `backend/open_webui/routers/auths.py` - API接口和业务逻辑
- `backend/open_webui/models/auths.py` - 数据模型和数据库操作
- `backend/open_webui/models/users.py` - 用户模型扩展
- `src/lib/apis/auths/index.ts` - 前端API接口
- `src/routes/auth/+page.svelte` - 登录页面组件

## 🔧 配置要求

### 1. 微信公众号配置
```python
WECHAT_APP_ID = "your_app_id"           # 公众号AppID
WECHAT_APP_SECRET = "your_app_secret"   # 公众号AppSecret
ENABLE_WECHAT_LOGIN = True              # 启用微信登录
```

### 2. 短信服务配置
```python
SMS_ACCESS_KEY_ID = "your_key_id"       # 阿里云AccessKey ID
SMS_ACCESS_KEY_SECRET = "your_secret"   # 阿里云AccessKey Secret
SMS_SIGN_NAME = "your_sign_name"        # 短信签名
SMS_TEMPLATE_CODE = "your_template"     # 短信模板
SMS_ENDPOINT = "dysmsapi.aliyuncs.com"  # 服务端点
```

### 3. 微信公众号服务器配置
- **URL**: `https://your-domain.com/api/v1/auths/wechat/follow-event`
- **Token**: 自定义token用于验证消息
- **消息类型**: 关注/取消关注事件

## 🚀 部署步骤

### 1. 现有系统升级
```bash
cd backend/open_webui
python -m alembic upgrade head
```

### 2. 新系统部署
- 使用新的迁移脚本进行完整初始化
- 配置微信公众号和短信服务
- 设置微信事件推送URL

### 3. 功能验证
- 测试邮箱登录
- 测试手机号登录
- 测试微信公众号关注登录
- 测试账号绑定功能

## 📋 测试清单

- [ ] 邮箱登录功能正常
- [ ] 手机号注册/登录功能正常
- [ ] 短信验证码发送和验证
- [ ] 微信公众号关注登录
- [ ] 微信登录后绑定手机号
- [ ] 手机号登录后绑定微信
- [ ] 用户数据迁移正确
- [ ] 绑定状态显示正确
- [ ] 多种方式登录同一账号

## 🔄 向后兼容性

- 原有用户数据自动迁移
- 原有邮箱登录方式保持不变
- API接口保持向后兼容
- 前端界面优雅降级

## ⚠️ 注意事项

1. **数据备份**: 升级前务必备份数据库
2. **微信配置**: 需要有微信公众号并完成配置
3. **短信服务**: 需要阿里云短信服务账号
4. **测试环境**: 建议先在测试环境验证功能
5. **用户通知**: 建议提前通知用户新功能

## 📞 技术支持

如遇到问题，请查看：
1. `DATABASE_MIGRATION_GUIDE.md` - 详细的迁移指南
2. 系统日志文件
3. 数据库迁移状态
4. 微信公众号配置状态

# 订阅系统变更摘要

## 最新更新

### 🆕 多订阅信息查询功能 (2024)

#### 新增功能
- **新增用户所有订阅记录查询接口**：`GET /api/v1/subscription/users/{user_id}/subscriptions`
- 支持分页查询用户的所有订阅记录（包括活跃、过期、已取消的订阅）
- 支持按状态过滤订阅记录
- 提供详细的订阅摘要信息

#### 接口详情

##### 1. 获取用户当前活跃订阅（原有接口）
```http
GET /api/v1/subscription/users/{user_id}/subscription
```
- 功能：获取用户当前活跃的订阅信息
- 返回：单个活跃订阅或免费套餐信息

##### 2. 获取用户所有订阅记录（新增接口）
```http
GET /api/v1/subscription/users/{user_id}/subscriptions?status=active&page=1&limit=10
```

**查询参数：**
- `status` (可选): 订阅状态过滤
  - `active` - 活跃订阅
  - `cancelled` - 已取消订阅  
  - `expired` - 已过期订阅
  - 不传 - 获取所有状态
- `page` (可选): 页码，默认为 1
- `limit` (可选): 每页数量，默认为 10，最大 50

**返回数据结构：**
```json
{
  "success": true,
  "data": {
    "subscriptions": [
      {
        "id": "sub_123",
        "user_id": "user_456",
        "plan_id": "premium",
        "plan": {
          "id": "premium",
          "name": "高级套餐",
          "description": "包含更多功能",
          "price": 99.0,
          "duration": 30,
          "credits": 1000
        },
        "status": "active",
        "start_date": 1704067200,
        "end_date": 1706659200,
        "created_at": 1704067200,
        "updated_at": 1704067200,
        "is_active": true,
        "is_expired": false,
        "days_remaining": 15
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 5,
      "total_pages": 1
    },
    "summary": {
      "total_subscriptions": 5,
      "active_subscriptions": 1,
      "expired_subscriptions": 3,
      "cancelled_subscriptions": 1
    }
  }
}
```

#### 权限控制
- 用户只能查看自己的订阅信息
- 管理员可以查看任意用户的订阅信息

#### 使用示例

##### 获取所有订阅记录
```bash
curl -X GET "http://localhost:8080/api/v1/subscription/users/user_123/subscriptions" \
  -H "Authorization: Bearer your_token"
```

##### 获取活跃订阅
```bash
curl -X GET "http://localhost:8080/api/v1/subscription/users/user_123/subscriptions?status=active" \
  -H "Authorization: Bearer your_token"
```

##### 分页查询已过期订阅
```bash
curl -X GET "http://localhost:8080/api/v1/subscription/users/user_123/subscriptions?status=expired&page=1&limit=5" \
  -H "Authorization: Bearer your_token"
```

#### 技术实现
- 在 `SubscriptionsTable` 类中新增 `get_user_all_subscriptions` 方法
- 支持 SQL 查询优化，一次性获取相关套餐信息
- 自动计算订阅状态和剩余天数
- 提供统计摘要信息

#### 向后兼容性
- 原有的单订阅查询接口保持不变
- 所有现有功能正常运行
- 新接口为可选使用

---

## 历史变更

### 订阅系统基础功能 (2024)
- 套餐管理（创建、更新、删除、查询）
- 用户订阅管理（购买、取消、续费）
- 兑换码系统
- 每日积分发放
- 支付记录管理
- 套餐积分系统

### 权限和安全
- 基于角色的访问控制
- 用户只能操作自己的订阅
- 管理员具有完整权限
- 支付回调验证

### 数据库设计
- 订阅计划表 (subscription_plans)
- 用户订阅表 (subscription_subscriptions)  
- 兑换码表 (subscription_redeem_codes)
- 支付记录表 (subscription_payments)
- 每日积分发放表 (subscription_daily_credit_grants)
- 套餐积分表 (subscription_credits) 