import datetime
import logging
import uuid
import time  # 添加这个导入
from typing import Optional, Dict, Any

from fastapi import Request, HTTPException
from decimal import Decimal
from open_webui.internal.db import Base, get_db

from open_webui.models.credits import Credits, TradeTickets
from open_webui.models.subscription import Payments, Subscriptions, Plans

# 添加正确的表模型导入
from open_webui.models.subscription import Subscription  # 添加这行
from open_webui.models.users import UserModel
from open_webui.utils.credit.ezfp import ezfp_client

log = logging.getLogger(__name__)


async def create_payment(
    request: Request,
    user: UserModel,
    payment_type: str,  # "credits" 或 "subscription"
    amount: float,
    pay_type: str,
    plan_id: Optional[str] = None,
    credits: Optional[int] = None,
) -> Dict[str, Any]:
    """
    统一的支付创建函数，用于创建积分支付或套餐支付
    """
    # 生成唯一交易号
    out_trade_no = (
        f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.{uuid.uuid4().hex}"
    )

    # 调用支付接口
    payment_detail = await ezfp_client.create_trade(
        pay_type=pay_type,
        out_trade_no=out_trade_no,
        amount=amount,
        client_ip=request.client.host,
        ua=request.headers.get("User-Agent"),
    )

    if payment_type == "subscription":
        if not plan_id:
            raise HTTPException(status_code=400, detail="订阅支付需要提供套餐ID")

        # 创建套餐支付记录
        Payments.create_payment(
            {
                "id": out_trade_no,
                "user_id": user.id,
                "amount": amount,
                "payment_type": "subscription",
                "plan_id": plan_id,
                "payment_method": pay_type,
                "status": "pending",
                "detail": payment_detail,
            }
        )
        # 查找支付记录
        payment = Payments.get_payment(out_trade_no)
        # 已经处理过的回调
        if payment.status != "pending":
            return "success"

        # 更新支付状态
        payment.status = "completed"
        payment.transaction_id = user.id
        payment.updated_at = int(datetime.datetime.now().timestamp())
        Payments.update_payment(payment.id, payment)

        # 根据支付类型处理后续逻辑

        if payment.payment_type == "subscription":
            # 处理套餐订阅
            # 处理套餐订阅
            plan = Plans.get_plan_by_id(payment.plan_id)
            if not plan:
                log.error(f"找不到套餐: {payment.plan_id}")
                return "success"
            now = int(datetime.datetime.now().timestamp())
            subscription_id = str(uuid.uuid4())
            subscription = {
                "id": subscription_id,
                "user_id": payment.user_id,
                "plan_id": payment.plan_id,
                "start_date": now,
                "end_date": now + (plan.duration * 86400),
                "status": "active",
            }
            Subscriptions.subscribe_user(subscription)
            # 新订阅逻辑

    else:
        raise HTTPException(status_code=400, detail="不支持的支付类型")

    return {"id": out_trade_no, "amount": amount, "detail": payment_detail}
