import datetime
import logging
import uuid
from typing import Optional, Dict, Any

from fastapi import Request, HTTPException
from decimal import Decimal

from open_webui.models.credits import Credits, TradeTickets
from open_webui.models.subscription import Payments, Subscriptions, Plans
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

    # 根据支付类型创建不同的记录
    if payment_type == "credits":
        # 创建积分支付记录
        TradeTickets.insert_new_ticket(
            id=out_trade_no,
            user_id=user.id,
            amount=Decimal(amount),
            detail=payment_detail,
        )

        # 创建统一支付记录
        Payments.create_payment(
            {
                "id": out_trade_no,
                "user_id": user.id,
                "amount": amount,
                "payment_type": "credits",
                "credits": credits,
                "payment_method": pay_type,
                "status": "pending",
                "detail": payment_detail,
            }
        )

    elif payment_type == "subscription":
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

    else:
        raise HTTPException(status_code=400, detail="不支持的支付类型")

    return {"id": out_trade_no, "amount": amount, "detail": payment_detail}


async def handle_payment_callback(callback_data: Dict[str, Any]) -> str:
    """
    统一的支付回调处理函数
    """
    if not ezfp_client.verify(callback_data):
        return "invalid signature"

    # 支付失败
    if callback_data["trade_status"] != "TRADE_SUCCESS":
        return "success"

    # 查找支付记录
    payment = Payments.get_payment(callback_data["out_trade_no"])
    if not payment:
        # 尝试查找旧的积分支付记录
        ticket = TradeTickets.get_ticket_by_id(callback_data["out_trade_no"])
        if not ticket:
            return "no payment record found"

        # 如果是旧的积分支付记录，按原来的方式处理
        if ticket.detail.get("callback"):
            return "success"

        ticket.detail["callback"] = callback_data
        TradeTickets.update_credit_by_id(ticket.id, ticket.detail)
        return "success"

    # 已经处理过的回调
    if payment.status != "pending":
        return "success"

    # 更新支付状态
    payment.status = "completed"
    payment.transaction_id = callback_data.get("transaction_id")
    payment.updated_at = int(datetime.datetime.now().timestamp())
    Payments.update_payment(payment.id, payment)

    # 根据支付类型处理后续逻辑
    if payment.payment_type == "credits":
        # 给用户增加积分
        Credits.add_credit_by_user_id(
            user_id=payment.user_id,
            amount=Decimal(payment.credits),
            detail={"desc": f"购买积分 {payment.credits}", "payment_id": payment.id},
        )

    elif payment.payment_type == "subscription":
        # 处理套餐订阅
        plan = Plans.get_plan_by_id(payment.plan_id)
        if not plan:
            log.error(f"找不到套餐: {payment.plan_id}")
            return "success"

        # 创建订阅
        now = int(datetime.datetime.now().timestamp())
        subscription_id = str(uuid.uuid4())
        subscription = {
            "id": subscription_id,
            "user_id": payment.user_id,
            "plan_id": payment.plan_id,
            "start_time": now,
            "end_time": now + (plan.duration * 86400),  # 转换天数为秒数
            "status": "active",
        }
        Subscriptions.subscribe_user(subscription)

        # 如果套餐包含积分，给用户增加积分
        if plan.credits > 0:
            Credits.add_credit_by_user_id(
                user_id=payment.user_id,
                amount=Decimal(plan.credits),
                detail={
                    "desc": f"套餐 {plan.name} 包含积分 {plan.credits}",
                    "subscription_id": subscription_id,
                    "payment_id": payment.id,
                },
            )

    return "success"
