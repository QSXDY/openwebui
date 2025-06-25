# 权限组系统升级文档

## 概述

本次升级将权限组系统从 **单组模式** 升级为 **多组模式**，允许用户加入多个企业，并实现按加入时间顺序的智能积分扣除机制。

## 🔄 主要变更

### 1. 数据库结构变更

#### 新增表：`user_group_membership`
- 支持用户与组的多对多关系
- 记录加入时间，用于积分扣除优先级排序
- 支持软删除（`is_active` 字段）

```sql
CREATE TABLE user_group_membership (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    group_id TEXT NOT NULL,
    joined_at BIGINT NOT NULL,      -- 加入时间（关键字段）
    is_active BOOLEAN DEFAULT TRUE,  -- 是否活跃
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
```

### 2. 业务逻辑变更

#### 🎯 积分扣除逻辑
**原逻辑**：用户只能在一个组，扣除该组管理员积分  
**新逻辑**：用户可在多个组，按加入时间顺序扣除积分

```
用户加入顺序：企业A (2024-01-01) → 企业B (2024-02-01) → 企业C (2024-03-01)
积分扣除优先级：企业A管理员 → 企业B管理员 → 企业C管理员 → 用户自己
```

#### 🏢 用户组关系管理
- 用户可以同时属于多个企业
- 退出企业时，自动调整积分扣除顺序
- 保持向后兼容性

## 📁 修改的文件

### 1. 数据库迁移
```
backend/open_webui/migrations/versions/add_user_group_membership.py
```
- 创建新的用户组关系表
- 添加必要的索引和约束

### 2. 模型层修改
```
backend/open_webui/models/groups.py
```
**新增方法**：
- `get_user_groups_ordered()` - 按加入时间获取用户所在组
- `add_user_to_group()` - 添加用户到组
- `remove_user_from_group()` - 从组中移除用户

**修改方法**：
- `get_user_group()` - 现在返回最早加入的组（向后兼容）
- `ensure_user_in_single_group()` - 改为确保用户在组内（不再限制单组）

### 3. 路由层修改
```
backend/open_webui/routers/groups.py
```
**新增API**：
- `POST /groups/id/{group_id}/add-user/{user_id}` - 添加用户到组
- `POST /groups/id/{group_id}/remove-user/{user_id}` - 从组移除用户
- `GET /groups/user/{user_id}/groups` - 获取用户所在组列表

**修改API**：
- `GET /groups/admin-credit` - 支持多组积分信息展示

### 4. 积分扣除逻辑修改
```
backend/open_webui/utils/credit/usage.py
```
- 修改 `CreditDeduct.__exit__()` 方法
- 实现按加入时间顺序的智能积分扣除
- 添加详细的日志记录

### 5. 数据迁移脚本
```
backend/migrate_group_memberships.py
```
- 将现有用户组关系迁移到新表
- 验证迁移结果的完整性

## 🚀 部署步骤

### 1. 运行数据库迁移
```bash
cd backend
alembic upgrade head
```

### 2. 运行数据迁移脚本
```bash
cd backend
python migrate_group_memberships.py
```

### 3. 重启应用
```bash
# 重启 OpenWebUI 后端服务
```

## 📖 新功能使用说明

### 1. 管理员操作

#### 添加用户到企业
```bash
curl -X POST "http://localhost:8080/api/v1/groups/id/{group_id}/add-user/{user_id}" \
  -H "Authorization: Bearer admin_token"
```

#### 从企业移除用户
```bash
curl -X POST "http://localhost:8080/api/v1/groups/id/{group_id}/remove-user/{user_id}" \
  -H "Authorization: Bearer admin_token"
```

#### 查看用户所在企业
```bash
curl -X GET "http://localhost:8080/api/v1/groups/user/{user_id}/groups" \
  -H "Authorization: Bearer admin_token"
```

### 2. 用户体验

#### 查看积分信息
```bash
curl -X GET "http://localhost:8080/api/v1/groups/admin-credit" \
  -H "Authorization: Bearer user_token"
```

**返回示例**：
```json
{
  "user_credit": 100,
  "admin_credit": 1000,
  "admin_id": "admin_123",
  "admin_name": "企业管理员",
  "group_id": "group_456",
  "group_name": "企业A",
  "groups": [
    {
      "id": "group_456",
      "name": "企业A",
      "admin_id": "admin_123",
      "admin_name": "企业管理员",
      "admin_credit": 1000
    },
    {
      "id": "group_789",
      "name": "企业B", 
      "admin_id": "admin_456",
      "admin_name": "企业B管理员",
      "admin_credit": 500
    }
  ]
}
```

## 🔄 积分扣除示例

### 场景描述
- 用户小明属于 3 个企业：
  - 企业A（2024-01-01 加入，管理员积分：1000）
  - 企业B（2024-02-01 加入，管理员积分：500）
  - 企业C（2024-03-01 加入，管理员积分：200）
- 小明自己的积分：100
- 本次消费：300 积分

### 扣除逻辑
1. **检查企业A管理员**：积分 1000 ≥ 300 ✅ → 扣除企业A管理员 300 积分
2. 如果企业A积分不足，检查企业B管理员
3. 如果企业B积分不足，检查企业C管理员  
4. 如果所有企业积分都不足，扣除用户自己的积分

### 日志输出
```
[credit_deduct] user: ming_123; actual_payer: admin_a; group: 企业A; tokens: 1000 500; cost: 300; subscription_used: 0; regular_used: 300
```

## ⚠️ 注意事项

### 1. 向后兼容性
- 现有 API 保持正常工作
- 现有单组用户无需额外操作
- `get_user_group()` 仍返回最早加入的组

### 2. 数据安全
- 软删除机制，不会丢失历史关系数据
- 迁移脚本包含完整性验证
- 支持回滚操作

### 3. 性能考虑
- 查询按加入时间排序，对大量组的用户有轻微性能影响
- 建议为活跃用户设置合理的组数量限制

### 4. 权限管理
- 新的用户组管理 API 需要管理员权限
- 用户只能查看自己的组信息
- 积分扣除遵循现有的安全策略

## 🐛 故障排除

### 常见问题

#### 1. 迁移失败
```bash
# 检查数据库连接
python -c "from open_webui.internal.db import get_db; print('数据库连接正常')"

# 重新运行迁移
python migrate_group_memberships.py
```

#### 2. 积分扣除异常
- 检查用户是否正确加入组
- 确认管理员积分余额
- 查看应用日志中的详细错误信息

#### 3. API 访问失败
- 确认用户权限（管理员/普通用户）
- 检查组ID和用户ID是否正确
- 验证 Bearer Token 有效性

## 📈 后续规划

### 可能的增强功能
1. **组优先级设置** - 允许用户自定义积分扣除顺序
2. **积分池共享** - 企业内积分共享机制
3. **组权限细化** - 不同组的不同权限级别
4. **批量操作** - 批量添加/移除用户
5. **组统计报表** - 企业积分使用统计

---

*本文档记录了权限组系统从单组到多组的完整升级过程。如有疑问，请参考代码注释或联系开发团队。* 