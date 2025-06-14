import pytest
import uuid
import time
from datetime import datetime, timedelta
from decimal import Decimal
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from open_webui.main import app  # 导入你的 FastAPI 应用

# 导入需要测试的模块
from open_webui.models.subscription import (
    Plans,
    Subscriptions,
    RedeemCodes,
    Payments,
    DailyCreditGrants,
    SubscriptionCreditsTable,
    PlanModel,
    SubscriptionModel,
    RedeemCodeModel,
    PaymentModel,
    DailyCreditGrantModel,
    SubscriptionCreditModel,
)
from open_webui.models.credits import Credits
from open_webui.models.users import UserModel
from open_webui.test.util.abstract_integration_test import AbstractIntegrationTest
from open_webui.test.util.mock_user import mock_webui_user


class TestSubscription(AbstractIntegrationTest):
    """套餐系统测试类"""

    BASE_PATH = "/api/v1/subscription"

    @classmethod
    def setup_class(cls):
        """测试类初始化"""
        super().setup_class()
        cls.client = TestClient(app)
        cls.test_user_id = "test_user_123"
        cls.admin_user_id = "admin_user_123"
        cls.test_plan_id = "test_plan_123"

    def setup_method(self):
        """每个测试方法前的初始化"""
        super().setup_method()
        # 清理测试数据
        self._cleanup_test_data()
        # 创建测试套餐
        self._create_test_plan()

    def teardown_method(self):
        """每个测试方法后的清理"""
        self._cleanup_test_data()

    def _cleanup_test_data(self):
        """清理测试数据"""
        try:
            # 清理测试用户的订阅、积分发放记录等
            with patch("open_webui.internal.db.get_db") as mock_db:
                mock_session = MagicMock()
                mock_db.return_value.__enter__.return_value = mock_session

                # 模拟清理操作
                mock_session.query.return_value.filter.return_value.delete.return_value = (
                    None
                )
                mock_session.commit.return_value = None
        except Exception as e:
            print(f"清理测试数据失败: {e}")

    def _create_test_plan(self):
        """创建测试套餐"""
        self.test_plan = PlanModel(
            id=self.test_plan_id,
            name="测试套餐",
            description="用于测试的套餐",
            price=99.99,
            duration=30,
            credits=1000,
            is_active=True,
            features=["feature1", "feature2"],
        )

    # ============== 套餐管理测试 ==============

    def test_create_plan_success(self):
        """测试创建套餐成功"""
        with mock_webui_user(id=self.admin_user_id, role="admin"):
            with patch.object(Plans, "create_plan") as mock_create:
                mock_create.return_value = self.test_plan

                plan_data = {
                    "name": "新套餐",
                    "description": "新套餐描述",
                    "price": 199.99,
                    "duration": 60,
                    "credits": 2000,
                    "features": ["premium_feature"],
                }

                response = self.client.post(self.create_url("/plans"), json=plan_data)

                assert response.status_code == 201
                result = response.json()
                assert result["success"] is True
                assert "plan" in result
                mock_create.assert_called_once()

    def test_create_plan_unauthorized(self):
        """测试非管理员创建套餐失败"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            plan_data = {"name": "新套餐", "description": "新套餐描述", "price": 199.99}

            response = self.client.post(self.create_url("/plans"), json=plan_data)

            assert response.status_code == 403

    def test_list_plans(self):
        """测试获取套餐列表"""
        with patch.object(Plans, "list_active_plans") as mock_list:
            mock_list.return_value = [self.test_plan]

            response = self.client.get(self.create_url("/plans"))

            assert response.status_code == 200
            result = response.json()
            assert result["success"] is True
            assert len(result["plans"]) == 1
            assert result["plans"][0]["id"] == self.test_plan_id

    def test_update_plan_success(self):
        """测试更新套餐成功"""
        with mock_webui_user(id=self.admin_user_id, role="admin"):
            with (
                patch.object(Plans, "get_plan_by_id") as mock_get,
                patch.object(Plans, "update_plan") as mock_update,
            ):

                mock_get.return_value = self.test_plan
                updated_plan = self.test_plan.model_copy()
                updated_plan.name = "更新后的套餐"
                mock_update.return_value = updated_plan

                update_data = {"name": "更新后的套餐"}

                response = self.client.put(
                    self.create_url(f"/plans/{self.test_plan_id}"), json=update_data
                )

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert result["data"]["name"] == "更新后的套餐"

    def test_delete_plan_success(self):
        """测试删除套餐成功"""
        with mock_webui_user(id=self.admin_user_id, role="admin"):
            with patch.object(Plans, "delete_plan") as mock_delete:
                mock_delete.return_value = {"success": True, "message": "删除成功"}

                response = self.client.delete(
                    self.create_url(f"/plans/{self.test_plan_id}")
                )

                assert response.status_code == 200
                mock_delete.assert_called_once_with(self.test_plan_id)

    # ============== 订阅测试 ==============

    def test_purchase_subscription_success(self):
        """测试购买套餐成功"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            with (
                patch.object(Plans, "get_plan_by_id") as mock_get_plan,
                patch("open_webui.utils.payment.create_payment") as mock_payment,
            ):

                mock_get_plan.return_value = self.test_plan
                mock_payment.return_value = {
                    "success": True,
                    "payment_id": "payment_123",
                    "payment_url": "https://pay.example.com/123",
                }

                purchase_data = {"plan_id": self.test_plan_id, "pay_type": "alipay"}

                response = self.client.post(
                    self.create_url("/subscriptions/purchase"), json=purchase_data
                )

                assert response.status_code == 201
                mock_payment.assert_called_once()

    def test_purchase_nonexistent_plan(self):
        """测试购买不存在的套餐"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            with patch.object(Plans, "get_plan_by_id") as mock_get_plan:
                mock_get_plan.return_value = None

                purchase_data = {"plan_id": "nonexistent_plan", "pay_type": "alipay"}

                response = self.client.post(
                    self.create_url("/subscriptions/purchase"), json=purchase_data
                )

                assert response.status_code == 404

    def test_get_user_subscription(self):
        """测试获取用户订阅信息"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            test_subscription = {
                "id": "sub_123",
                "user_id": self.test_user_id,
                "plan_id": self.test_plan_id,
                "status": "active",
                "start_date": int(time.time()),
                "end_date": int(time.time()) + 30 * 24 * 3600,
            }

            with patch.object(Subscriptions, "get_user_subscription") as mock_get:
                mock_get.return_value = test_subscription

                response = self.client.get(
                    self.create_url(f"/users/{self.test_user_id}/subscription")
                )

                assert response.status_code == 200
                mock_get.assert_called_once_with(self.test_user_id)

    def test_cancel_subscription_success(self):
        """测试取消订阅成功"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            subscription_id = "sub_123"
            test_subscription = SubscriptionModel(
                id=subscription_id,
                user_id=self.test_user_id,
                plan_id=self.test_plan_id,
                status="active",
                start_date=int(time.time()),
                end_date=int(time.time()) + 30 * 24 * 3600,
            )

            with (
                patch.object(Subscriptions, "get_subscription_by_id") as mock_get,
                patch.object(Subscriptions, "cancel_subscription") as mock_cancel,
            ):

                mock_get.return_value = test_subscription
                mock_cancel.return_value = {"success": True, "message": "取消成功"}

                response = self.client.post(
                    self.create_url("/subscriptions/cancel"),
                    json={"subscription_id": subscription_id},
                )

                assert response.status_code == 200
                mock_cancel.assert_called_once()

    # ============== 每日积分发放测试 ==============

    def test_process_daily_credits_admin(self):
        """测试管理员手动触发每日积分发放"""
        with mock_webui_user(id=self.admin_user_id, role="admin"):
            with patch.object(
                DailyCreditGrants, "process_daily_grants_for_all_users"
            ) as mock_process:
                mock_process.return_value = {
                    "success": True,
                    "processed_users": 10,
                    "total_credits_granted": 5000,
                }

                response = self.client.post(self.create_url("/daily-credits/process"))

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert result["processed_users"] == 10

    def test_grant_daily_credits_to_user_success(self):
        """测试为指定用户发放每日积分成功"""
        with mock_webui_user(id=self.admin_user_id, role="admin"):
            test_subscription = SubscriptionModel(
                id="sub_123",
                user_id=self.test_user_id,
                plan_id=self.test_plan_id,
                status="active",
                start_date=int(time.time()),
                end_date=int(time.time()) + 30 * 24 * 3600,
            )

            test_grant = DailyCreditGrantModel(
                id="grant_123",
                user_id=self.test_user_id,
                subscription_id="sub_123",
                plan_id=self.test_plan_id,
                grant_date=int(time.time()),
                credits_granted=1000,
            )

            with (
                patch.object(
                    Subscriptions, "get_user_active_subscription"
                ) as mock_get_sub,
                patch.object(Plans, "get_plan_by_id") as mock_get_plan,
                patch.object(DailyCreditGrants, "grant_daily_credits") as mock_grant,
            ):

                mock_get_sub.return_value = test_subscription
                mock_get_plan.return_value = self.test_plan
                mock_grant.return_value = test_grant

                response = self.client.post(
                    self.create_url(f"/daily-credits/grant/{self.test_user_id}")
                )

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert "成功为用户" in result["message"]

    def test_grant_daily_credits_no_subscription(self):
        """测试为没有订阅的用户发放积分失败"""
        with mock_webui_user(id=self.admin_user_id, role="admin"):
            with patch.object(
                Subscriptions, "get_user_active_subscription"
            ) as mock_get_sub:
                mock_get_sub.return_value = None

                response = self.client.post(
                    self.create_url(f"/daily-credits/grant/{self.test_user_id}")
                )

                assert response.status_code == 404

    def test_get_user_credit_grant_history(self):
        """测试获取用户积分发放历史"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            mock_history = {
                "success": True,
                "data": [
                    {
                        "id": "grant_1",
                        "grant_date": int(time.time()),
                        "credits_granted": 1000,
                    }
                ],
                "total": 1,
                "page": 1,
                "limit": 10,
            }

            with patch.object(
                DailyCreditGrants, "get_user_grant_history"
            ) as mock_get_history:
                mock_get_history.return_value = mock_history

                response = self.client.get(
                    self.create_url(f"/daily-credits/history/{self.test_user_id}")
                )

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert len(result["data"]) == 1

    def test_check_daily_credit_status(self):
        """测试检查用户今日积分发放状态"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            test_subscription = SubscriptionModel(
                id="sub_123",
                user_id=self.test_user_id,
                plan_id=self.test_plan_id,
                status="active",
                start_date=int(time.time()),
                end_date=int(time.time()) + 30 * 24 * 3600,
            )

            with (
                patch.object(
                    Subscriptions, "get_user_active_subscription"
                ) as mock_get_sub,
                patch.object(
                    DailyCreditGrants, "has_granted_today"
                ) as mock_has_granted,
                patch.object(Plans, "get_plan_by_id") as mock_get_plan,
            ):

                mock_get_sub.return_value = test_subscription
                mock_has_granted.return_value = False
                mock_get_plan.return_value = self.test_plan

                response = self.client.get(
                    self.create_url(f"/daily-credits/status/{self.test_user_id}")
                )

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert result["has_active_subscription"] is True
                assert result["granted_today"] is False

    # ============== 兑换码测试 ==============

    def test_generate_redeem_codes_success(self):
        """测试生成兑换码成功"""
        with mock_webui_user(id=self.admin_user_id, role="admin"):
            with patch.object(RedeemCodes, "create_redeem_codes") as mock_create:
                mock_codes = [
                    {"code": "ABCD-EFGH", "plan_id": self.test_plan_id},
                    {"code": "IJKL-MNOP", "plan_id": self.test_plan_id},
                ]
                mock_create.return_value = mock_codes

                generate_data = {
                    "plan_id": self.test_plan_id,
                    "count": 2,
                    "duration_days": 30,
                }

                response = self.client.post(
                    self.create_url("/redeem-codes"), json=generate_data
                )

                assert response.status_code == 201
                result = response.json()
                assert result["success"] is True
                assert len(result["data"]) == 2

    def test_redeem_code_success(self):
        """测试兑换码兑换成功"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            test_subscription = SubscriptionModel(
                id="sub_123",
                user_id=self.test_user_id,
                plan_id=self.test_plan_id,
                status="active",
                start_date=int(time.time()),
                end_date=int(time.time()) + 30 * 24 * 3600,
            )

            test_grant = DailyCreditGrantModel(
                id="grant_123",
                user_id=self.test_user_id,
                subscription_id="sub_123",
                plan_id=self.test_plan_id,
                grant_date=int(time.time()),
                credits_granted=1000,
            )

            with (
                patch.object(RedeemCodes, "redeem_code") as mock_redeem,
                patch.object(Plans, "get_plan_by_id") as mock_get_plan,
                patch.object(DailyCreditGrants, "grant_daily_credits") as mock_grant,
            ):

                mock_redeem.return_value = (test_subscription, "兑换成功")
                mock_get_plan.return_value = self.test_plan
                mock_grant.return_value = test_grant

                redeem_data = {"code": "ABCD-EFGH"}

                response = self.client.post(
                    self.create_url("/redeem"), json=redeem_data
                )

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert result["message"] == "兑换成功"

    def test_redeem_invalid_code(self):
        """测试兑换无效兑换码"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            with patch.object(RedeemCodes, "redeem_code") as mock_redeem:
                mock_redeem.return_value = (None, "兑换码无效或已使用")

                redeem_data = {"code": "INVALID-CODE"}

                response = self.client.post(
                    self.create_url("/redeem"), json=redeem_data
                )

                assert response.status_code == 400

    def test_list_redeem_codes_admin(self):
        """测试管理员获取兑换码列表"""
        with mock_webui_user(id=self.admin_user_id, role="admin"):
            mock_codes_data = {
                "success": True,
                "data": [
                    {"code": "ABCD-EFGH", "is_used": False},
                    {"code": "IJKL-MNOP", "is_used": True},
                ],
                "total": 2,
                "page": 1,
                "limit": 10,
            }

            with patch.object(RedeemCodes, "get_redeem_codes") as mock_get_codes:
                mock_get_codes.return_value = mock_codes_data

                response = self.client.get(
                    self.create_url("/redeem-codes?page=1&limit=10")
                )

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert len(result["data"]) == 2

    # ============== 套餐积分系统测试 ==============

    def test_subscription_credits_creation(self):
        """测试套餐积分记录创建"""
        subscription_credit_data = SubscriptionCreditModel(
            user_id=self.test_user_id,
            subscription_id="sub_123",
            plan_id=self.test_plan_id,
            total_credits=1000,
            remaining_credits=1000,
            consumed_credits=0,
            start_date=int(time.time()),
            end_date=int(time.time()) + 30 * 24 * 3600,
        )

        with patch.object(
            SubscriptionCreditsTable, "create_subscription_credit"
        ) as mock_create:
            mock_create.return_value = subscription_credit_data

            credits_table = SubscriptionCreditsTable()
            result = credits_table.create_subscription_credit(
                user_id=self.test_user_id,
                subscription_id="sub_123",
                plan_id=self.test_plan_id,
                total_credits=1000,
                start_date=int(time.time()),
                end_date=int(time.time()) + 30 * 24 * 3600,
            )

            assert result is not None
            assert result.total_credits == 1000
            assert result.remaining_credits == 1000

    def test_subscription_credits_consumption(self):
        """测试套餐积分消费"""
        with patch.object(SubscriptionCreditsTable, "consume_credits") as mock_consume:
            mock_consume.return_value = True

            credits_table = SubscriptionCreditsTable()
            result = credits_table.consume_credits(
                user_id=self.test_user_id, credits_amount=100
            )

            assert result is True
            mock_consume.assert_called_once_with(
                user_id=self.test_user_id, credits_amount=100
            )

    def test_get_total_active_credits(self):
        """测试获取用户总的活跃套餐积分"""
        with patch.object(
            SubscriptionCreditsTable, "get_total_active_credits"
        ) as mock_get_total:
            mock_get_total.return_value = 2500

            credits_table = SubscriptionCreditsTable()
            total_credits = credits_table.get_total_active_credits(self.test_user_id)

            assert total_credits == 2500
            mock_get_total.assert_called_once_with(self.test_user_id)

    def test_expire_subscription_credits(self):
        """测试套餐积分过期处理"""
        with patch.object(
            SubscriptionCreditsTable, "expire_subscription_credits"
        ) as mock_expire:
            mock_expire.return_value = 3  # 返回过期的记录数

            credits_table = SubscriptionCreditsTable()
            expired_count = credits_table.expire_subscription_credits()

            assert expired_count == 3
            mock_expire.assert_called_once()

    # ============== 支付记录测试 ==============

    def test_get_payment_detail_success(self):
        """测试获取支付记录详情成功"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            payment_id = "payment_123"
            test_payment = PaymentModel(
                id=payment_id,
                user_id=self.test_user_id,
                amount=99.99,
                payment_type="subscription",
                plan_id=self.test_plan_id,
                status="completed",
                payment_method="alipay",
            )

            with (
                patch.object(Payments, "get_payment") as mock_get_payment,
                patch.object(Plans, "get_plan_by_id") as mock_get_plan,
            ):

                mock_get_payment.return_value = test_payment
                mock_get_plan.return_value = self.test_plan

                response = self.client.get(self.create_url(f"/payments/{payment_id}"))

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert result["data"]["payment"]["id"] == payment_id
                assert result["data"]["plan"] is not None

    def test_get_payment_detail_unauthorized(self):
        """测试获取他人支付记录失败"""
        with mock_webui_user(id="other_user", role="user"):
            payment_id = "payment_123"
            test_payment = PaymentModel(
                id=payment_id,
                user_id=self.test_user_id,  # 不同的用户ID
                amount=99.99,
                payment_type="subscription",
                status="completed",
                payment_method="alipay",
            )

            with patch.object(Payments, "get_payment") as mock_get_payment:
                mock_get_payment.return_value = test_payment

                response = self.client.get(self.create_url(f"/payments/{payment_id}"))

                assert response.status_code == 403

    # ============== 集成测试 ==============

    def test_complete_subscription_flow(self):
        """测试完整的套餐订阅流程"""
        with mock_webui_user(id=self.test_user_id, role="user"):
            # 1. 获取套餐列表
            with patch.object(Plans, "list_active_plans") as mock_list_plans:
                mock_list_plans.return_value = [self.test_plan]

                plans_response = self.client.get(self.create_url("/plans"))
                assert plans_response.status_code == 200

            # 2. 购买套餐
            with (
                patch.object(Plans, "get_plan_by_id") as mock_get_plan,
                patch("open_webui.utils.payment.create_payment") as mock_payment,
            ):

                mock_get_plan.return_value = self.test_plan
                mock_payment.return_value = {
                    "success": True,
                    "payment_id": "payment_123",
                }

                purchase_response = self.client.post(
                    self.create_url("/subscriptions/purchase"),
                    json={"plan_id": self.test_plan_id, "pay_type": "alipay"},
                )
                assert purchase_response.status_code == 201

            # 3. 模拟支付完成后的订阅激活和积分发放
            test_subscription = SubscriptionModel(
                id="sub_123",
                user_id=self.test_user_id,
                plan_id=self.test_plan_id,
                status="active",
                start_date=int(time.time()),
                end_date=int(time.time()) + 30 * 24 * 3600,
            )

            # 4. 检查订阅状态
            with patch.object(Subscriptions, "get_user_subscription") as mock_get_sub:
                mock_get_sub.return_value = test_subscription.model_dump()

                subscription_response = self.client.get(
                    self.create_url(f"/users/{self.test_user_id}/subscription")
                )
                assert subscription_response.status_code == 200

            # 5. 检查积分发放状态
            with (
                patch.object(
                    Subscriptions, "get_user_active_subscription"
                ) as mock_get_active,
                patch.object(
                    DailyCreditGrants, "has_granted_today"
                ) as mock_has_granted,
                patch.object(Plans, "get_plan_by_id") as mock_get_plan,
            ):

                mock_get_active.return_value = test_subscription
                mock_has_granted.return_value = True  # 已发放
                mock_get_plan.return_value = self.test_plan

                status_response = self.client.get(
                    self.create_url(f"/daily-credits/status/{self.test_user_id}")
                )
                assert status_response.status_code == 200
                result = status_response.json()
                assert result["granted_today"] is True


if __name__ == "__main__":
    pytest.main(["-v", __file__])
