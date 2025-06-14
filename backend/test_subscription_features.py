from open_webui.models.credits import Credit, CreditLog, TradeTicket
from open_webui.models.subscription import (
    Plan,
    Subscription,
    RedeemCode,
    Payment,
    DailyCreditGrant,
    SubscriptionCredit,
)


def test_credit_grants(
    user_id="68586a84-58aa-4c8a-ace3-aff7404a7c8d", plan_id="765d6c2d"
):
    """测试积分发放逻辑"""
    print("\n=== 测试积分发放 ===")

    # 1. 初始化用户积分
    Credit.init_credit_by_user_id(user_id)
    initial_credits = Credit.get_credit_by_user_id(user_id).credit

    # 2. 发放积分
    try:
        grant = DailyCreditGrant.grant_daily_credits(
            user_id=user_id, plan_id=plan_id, credits_amount=100
        )
        new_credits = Credit.get_credit_by_user_id(user_id).credit
        assert new_credits > initial_credits, "积分未增加"
        print(f"✅ 积分发放成功 (当前: {new_credits})")
    except Exception as e:
        print(f"❌ 积分发放失败: {e}")
        return False

    return True


test_credit_grants()
