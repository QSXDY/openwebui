import time
import uuid
from decimal import Decimal
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    Numeric,
    String,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
)

from open_webui.internal.db import Base, get_db

####################
# Subscription DB Schema
####################


class Plan(Base):
    __tablename__ = "subscription_plans"

    id = Column(String, primary_key=True)
    name = Column(String(100), nullable=False)
    price = Column(Numeric(precision=24, scale=12), default=0)
    features = Column(JSON)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(BigInteger, default=lambda: int(time.time()))
    updated_at = Column(
        BigInteger, default=lambda: int(time.time()), onupdate=lambda: int(time.time())
    )


class Subscription(Base):
    __tablename__ = "subscription_subscriptions"

    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False, index=True)
    plan_id = Column(String, ForeignKey("subscription_plans.id"))
    status = Column(String(20), default="active")  # active, cancelled, expired
    start_date = Column(BigInteger, nullable=False)
    end_date = Column(BigInteger, nullable=False)
    created_at = Column(BigInteger, default=lambda: int(time.time()))
    updated_at = Column(
        BigInteger, default=lambda: int(time.time()), onupdate=lambda: int(time.time())
    )


class RedeemCode(Base):
    __tablename__ = "subscription_redeem_codes"

    code = Column(String, primary_key=True)
    plan_id = Column(String, ForeignKey("subscription_plans.id"))
    duration_days = Column(BigInteger, default=30)
    is_used = Column(Boolean, default=False)
    used_by = Column(String, nullable=True)
    used_at = Column(BigInteger, nullable=True)
    expires_at = Column(BigInteger, nullable=True)
    created_at = Column(BigInteger, default=lambda: int(time.time()))


class Payment(Base):
    __tablename__ = "subscription_payments"

    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False, index=True)
    plan_id = Column(String, ForeignKey("subscription_plans.id"))
    amount = Column(Numeric(precision=24, scale=12), default=0)
    payment_method = Column(String(50), default="lantupay")
    transaction_id = Column(String, nullable=True)
    status = Column(
        String(20), default="pending"
    )  # pending, completed, failed, refunded
    completed_at = Column(BigInteger, nullable=True)
    created_at = Column(BigInteger, default=lambda: int(time.time()))
    updated_at = Column(
        BigInteger, default=lambda: int(time.time()), onupdate=lambda: int(time.time())
    )


####################
# Forms
####################


class PlanModel(BaseModel):
    id: str
    name: str
    description: str
    price: float
    duration: int  # 套餐持续时间（天）
    is_active: bool = True
    features: List[str] = []
    credits: int = 0  # 套餐包含的积分数量
    created_at: int = Field(default_factory=lambda: int(time.time()))
    updated_at: int = Field(default_factory=lambda: int(time.time()))


class SubscriptionModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    user_id: str
    plan_id: str
    status: str = Field(default="active")
    start_date: int
    end_date: int
    created_at: int = Field(default_factory=lambda: int(time.time()))
    updated_at: int = Field(default_factory=lambda: int(time.time()))


class RedeemCodeModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    code: str
    plan_id: str
    duration_days: int = Field(default=30)
    is_used: bool = Field(default=False)
    used_by: Optional[str] = Field(default=None)
    used_at: Optional[int] = Field(default=None)
    expires_at: Optional[int] = Field(default=None)
    created_at: int = Field(default_factory=lambda: int(time.time()))


class PaymentModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    user_id: str
    amount: float
    payment_type: str  # subscription, credits
    plan_id: Optional[str] = None  # 如果是订阅支付，关联的套餐ID
    credits: Optional[int] = None  # 如果是积分支付，购买的积分数量
    status: str = "pending"  # pending, completed, failed
    payment_method: str  # 支付方式，例如 alipay, wechat
    transaction_id: Optional[str] = None  # 第三方支付平台的交易ID
    created_at: int = Field(default_factory=lambda: int(time.time()))
    updated_at: int = Field(default_factory=lambda: int(time.time()))


####################
# Tables
####################


class PlansTable:
    def create_plan(self, plan_data: PlanModel) -> PlanModel:
        try:
            with get_db() as db:
                plan = Plan(**plan_data.model_dump())
                db.add(plan)
                db.commit()
                db.refresh(plan)
                return PlanModel.model_validate(plan)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_plan_by_id(self, plan_id: str) -> Optional[PlanModel]:
        try:
            with get_db() as db:
                plan = db.query(Plan).filter(Plan.id == plan_id).first()
                return PlanModel.model_validate(plan) if plan else None
        except Exception:
            return None

    def list_active_plans(self) -> List[PlanModel]:
        try:
            with get_db() as db:
                plans = db.query(Plan).filter(Plan.is_active == True).all()
                return [PlanModel.model_validate(plan) for plan in plans]
        except Exception:
            return []

    def update_plan(self, plan_id: str, update_data: PlanModel) -> Optional[PlanModel]:
        try:
            with get_db() as db:
                db.query(Plan).filter(Plan.id == plan_id).update(
                    update_data.model_dump(exclude_unset=True),
                    synchronize_session=False,
                )
                db.commit()
                return self.get_plan_by_id(plan_id)
        except Exception:
            return None

    def delete_plan(self, plan_id: str) -> Dict[str, Any]:
        """删除套餐"""
        try:
            with get_db() as db:
                plan = db.query(Plan).filter(Plan.id == plan_id).first()
                if not plan:
                    raise HTTPException(status_code=404, detail="套餐不存在")

                # 检查是否有用户正在使用此套餐
                active_subscriptions = (
                    db.query(Subscription)
                    .filter(
                        Subscription.plan_id == plan_id, Subscription.status == "active"
                    )
                    .count()
                )

                if active_subscriptions > 0:
                    # 软删除，将套餐标记为非活跃
                    plan.is_active = False
                    db.commit()
                    return {"success": True, "message": "套餐已停用，但仍有用户在使用"}
                else:
                    # 硬删除
                    db.delete(plan)
                    db.commit()
                    return {"success": True, "message": "套餐已删除"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


Plans = PlansTable()


class SubscriptionsTable:
    def create_subscription(self, sub_data: SubscriptionModel) -> SubscriptionModel:
        try:
            with get_db() as db:
                subscription = Subscription(**sub_data.model_dump())
                db.add(subscription)
                db.commit()
                db.refresh(subscription)
                return SubscriptionModel.model_validate(subscription)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_subscription_by_id(self, sub_id: str) -> Optional[SubscriptionModel]:
        try:
            with get_db() as db:
                sub = db.query(Subscription).filter(Subscription.id == sub_id).first()
                return SubscriptionModel.model_validate(sub) if sub else None
        except Exception:
            return None

    def get_user_active_subscription(self, user_id: str) -> Optional[SubscriptionModel]:
        try:
            with get_db() as db:
                sub = (
                    db.query(Subscription)
                    .filter(
                        Subscription.user_id == user_id, Subscription.status == "active"
                    )
                    .first()
                )
                return SubscriptionModel.model_validate(sub) if sub else None
        except Exception:
            return None

    def get_user_subscription(self, user_id: str) -> Dict[str, Any]:
        """获取用户当前订阅信息"""
        try:
            with get_db() as db:
                subscription = (
                    db.query(Subscription)
                    .filter(
                        Subscription.user_id == user_id,
                        Subscription.status == "active",
                        Subscription.end_date > int(time.time()),
                    )
                    .first()
                )

                if not subscription:
                    # 如果没有活跃订阅，返回免费套餐
                    free_plan = db.query(Plan).filter(Plan.id == "free").first()
                    return {
                        "success": True,
                        "subscription": {
                            "user_id": user_id,
                            "plan_id": "free",
                            "plan": (
                                PlanModel.model_validate(free_plan).model_dump()
                                if free_plan
                                else None
                            ),
                            "status": "active",
                            "is_subscribed": False,
                        },
                    }

                # 获取套餐详情
                plan = db.query(Plan).filter(Plan.id == subscription.plan_id).first()

                return {
                    "success": True,
                    "subscription": {
                        "id": subscription.id,
                        "user_id": subscription.user_id,
                        "plan_id": subscription.plan_id,
                        "plan": (
                            PlanModel.model_validate(plan).model_dump()
                            if plan
                            else None
                        ),
                        "status": subscription.status,
                        "start_date": subscription.start_date,
                        "end_date": subscription.end_date,
                        "is_subscribed": True,
                    },
                }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def subscribe_user(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """为用户订阅套餐"""
        try:
            user_id = data.get("user_id")
            plan_id = data.get("plan_id")
            duration_days = data.get("duration_days", 30)

            if not user_id or not plan_id:
                raise HTTPException(status_code=400, detail="用户ID和套餐ID不能为空")

            with get_db() as db:
                # 检查套餐是否存在
                plan = db.query(Plan).filter(Plan.id == plan_id).first()
                if not plan:
                    raise HTTPException(status_code=404, detail="套餐不存在")

                # 检查用户是否已有活跃订阅
                start_date = int(time.time())
                end_date = start_date + duration_days * 86400

                existing_subscription = (
                    db.query(Subscription)
                    .filter(
                        Subscription.user_id == user_id,
                        Subscription.status == "active",
                        Subscription.end_date > int(time.time()),
                    )
                    .first()
                )

                if existing_subscription:
                    # 如果已有订阅，更新套餐和结束日期
                    existing_subscription.plan_id = plan_id
                    existing_subscription.end_date = end_date
                    existing_subscription.updated_at = int(time.time())
                    subscription_id = existing_subscription.id
                    db.commit()
                else:
                    # 创建新订阅
                    subscription_id = str(uuid.uuid4())
                    new_subscription = Subscription(
                        id=subscription_id,
                        user_id=user_id,
                        plan_id=plan_id,
                        status="active",
                        start_date=start_date,
                        end_date=end_date,
                    )
                    db.add(new_subscription)
                    db.commit()

                return {
                    "success": True,
                    "subscription": {
                        "id": subscription_id,
                        "user_id": user_id,
                        "plan_id": plan_id,
                        "status": "active",
                        "start_date": start_date,
                        "end_date": end_date,
                    },
                }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def cancel_subscription(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """取消用户订阅"""
        try:
            user_id = data.get("user_id")

            if not user_id:
                raise HTTPException(status_code=400, detail="用户ID不能为空")

            with get_db() as db:
                # 查找用户的活跃订阅
                subscription = (
                    db.query(Subscription)
                    .filter(
                        Subscription.user_id == user_id, Subscription.status == "active"
                    )
                    .first()
                )

                if not subscription:
                    raise HTTPException(status_code=404, detail="未找到活跃订阅")

                # 更新订阅状态
                subscription.status = "cancelled"
                subscription.updated_at = int(time.time())
                db.commit()

                return {"success": True, "message": "订阅已取消"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


Subscriptions = SubscriptionsTable()


class RedeemCodesTable:
    def create_redeem_code(self, code_data: RedeemCodeModel) -> RedeemCodeModel:
        try:
            with get_db() as db:
                code = RedeemCode(**code_data.model_dump())
                db.add(code)
                db.commit()
                db.refresh(code)
                return RedeemCodeModel.model_validate(code)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_redeem_code(self, code: str) -> Optional[RedeemCodeModel]:
        try:
            with get_db() as db:
                redeem_code = (
                    db.query(RedeemCode).filter(RedeemCode.code == code).first()
                )
                return (
                    RedeemCodeModel.model_validate(redeem_code) if redeem_code else None
                )
        except Exception:
            return None

    def redeem_code(self, code: str, user_id: str) -> Optional[SubscriptionModel]:
        try:
            with get_db() as db:
                redeem_code = (
                    db.query(RedeemCode)
                    .filter(
                        RedeemCode.code == code,
                        RedeemCode.is_used == False,
                        (RedeemCode.expires_at == None)
                        | (RedeemCode.expires_at >= int(time.time())),
                    )
                    .first()
                )

                if not redeem_code:
                    return None

                plan = db.query(Plan).filter(Plan.id == redeem_code.plan_id).first()
                if not plan:
                    return None

                start_date = int(time.time())
                end_date = start_date + redeem_code.duration_days * 86400

                subscription = Subscription(
                    user_id=user_id,
                    plan_id=redeem_code.plan_id,
                    start_date=start_date,
                    end_date=end_date,
                    status="active",
                )
                db.add(subscription)

                db.query(RedeemCode).filter(RedeemCode.code == code).update(
                    {"is_used": True, "used_by": user_id, "used_at": start_date}
                )

                db.commit()
                return SubscriptionModel.model_validate(subscription)
        except Exception:
            return None


RedeemCodes = RedeemCodesTable()


class PaymentsTable:
    def create_payment(self, payment_data: PaymentModel) -> PaymentModel:
        try:
            with get_db() as db:
                payment = Payment(**payment_data.model_dump())
                db.add(payment)
                db.commit()
                db.refresh(payment)
                return PaymentModel.model_validate(payment)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_payment_by_id(self, payment_id: str) -> Optional[PaymentModel]:
        try:
            with get_db() as db:
                payment = db.query(Payment).filter(Payment.id == payment_id).first()
                return PaymentModel.model_validate(payment) if payment else None
        except Exception:
            return None

    def update_payment_status(
        self, payment_id: str, status: str, transaction_id: Optional[str] = None
    ) -> Optional[PaymentModel]:
        try:
            update_data = {"status": status, "updated_at": int(time.time())}
            if status == "completed":
                update_data["completed_at"] = int(time.time())
            if transaction_id:
                update_data["transaction_id"] = transaction_id

            with get_db() as db:
                db.query(Payment).filter(Payment.id == payment_id).update(
                    update_data, synchronize_session=False
                )
                db.commit()
                return self.get_payment_by_id(payment_id)
        except Exception:
            return None

    def get_redeem_codes(self, page: int = 1, limit: int = 10) -> Dict[str, Any]:
        """获取兑换码列表"""
        try:
            with get_db() as db:
                total = db.query(RedeemCode).count()
                codes = (
                    db.query(RedeemCode)
                    .order_by(RedeemCode.created_at.desc())
                    .offset((page - 1) * limit)
                    .limit(limit)
                    .all()
                )

                return {
                    "success": True,
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "codes": [
                        RedeemCodeModel.model_validate(code).model_dump()
                        for code in codes
                    ],
                }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def create_redeem_codes(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """创建兑换码"""
        try:
            plan_id = data.get("plan_id")
            duration_days = data.get("duration_days", 30)
            count = data.get("count", 1)
            expires_at = data.get("expires_at")

            if not plan_id:
                raise HTTPException(status_code=400, detail="套餐ID不能为空")

            with get_db() as db:
                # 检查套餐是否存在
                plan = db.query(Plan).filter(Plan.id == plan_id).first()
                if not plan:
                    raise HTTPException(status_code=404, detail="套餐不存在")

                # 如果提供了过期时间，转换为时间戳
                if expires_at:
                    try:
                        if isinstance(expires_at, str):
                            expires_at = int(
                                datetime.fromisoformat(
                                    expires_at.replace("Z", "+00:00")
                                ).timestamp()
                            )
                    except:
                        expires_at = int(time.time()) + 90 * 86400  # 默认90天有效期
                else:
                    expires_at = int(time.time()) + 90 * 86400

                # 生成兑换码
                codes = []
                for _ in range(count):
                    code = f"sk-{uuid.uuid4().hex[:8].upper()}"
                    new_code = RedeemCode(
                        code=code,
                        plan_id=plan_id,
                        duration_days=duration_days,
                        expires_at=expires_at,
                    )
                    db.add(new_code)
                    codes.append(code)

                db.commit()

                return {"success": True, "codes": codes}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def delete_redeem_code(self, code: str) -> Dict[str, Any]:
        """删除兑换码"""
        try:
            with get_db() as db:
                redeem_code = (
                    db.query(RedeemCode).filter(RedeemCode.code == code).first()
                )

                if not redeem_code:
                    raise HTTPException(status_code=404, detail="兑换码不存在")

                db.delete(redeem_code)
                db.commit()

                return {"success": True, "message": "兑换码已删除"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


RedeemCodes = RedeemCodesTable()


class PaymentsTable:
    def create_payment(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """创建支付订单"""
        try:
            user_id = data.get("user_id")
            plan_id = data.get("plan_id")
            payment_method = data.get("payment_method", "lantupay")

            if not user_id or not plan_id:
                raise HTTPException(status_code=400, detail="用户ID和套餐ID不能为空")

            with get_db() as db:
                # 检查套餐是否存在
                plan = db.query(Plan).filter(Plan.id == plan_id).first()
                if not plan:
                    raise HTTPException(status_code=404, detail="套餐不存在")

                # 创建支付记录
                payment_id = str(uuid.uuid4())
                new_payment = Payment(
                    id=payment_id,
                    user_id=user_id,
                    plan_id=plan_id,
                    amount=plan.price,
                    payment_method=payment_method,
                    status="pending",
                )
                db.add(new_payment)
                db.commit()

                # 这里可以集成实际的支付网关
                # 例如调用蓝兔支付API创建支付链接

                return {
                    "success": True,
                    "payment": {
                        "id": payment_id,
                        "amount": plan.price,
                        "status": "pending",
                        "payment_url": f"/api/subscription/pay/{payment_id}",  # 示例支付URL
                    },
                }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def payment_callback(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """支付回调处理"""
        try:
            payment_id = data.get("payment_id")
            transaction_id = data.get("transaction_id")
            status = data.get("status")

            if not payment_id:
                raise HTTPException(status_code=400, detail="支付ID不能为空")

            with get_db() as db:
                # 查找支付记录
                payment = db.query(Payment).filter(Payment.id == payment_id).first()

                if not payment:
                    raise HTTPException(status_code=404, detail="支付记录不存在")

                # 更新支付状态
                payment.status = status
                payment.transaction_id = transaction_id

                if status == "completed":
                    payment.completed_at = int(time.time())

                    # 为用户订阅套餐
                    start_date = int(time.time())
                    end_date = start_date + 30 * 86400  # 默认30天

                    # 检查用户是否已有活跃订阅
                    existing_subscription = (
                        db.query(Subscription)
                        .filter(
                            Subscription.user_id == payment.user_id,
                            Subscription.status == "active",
                            Subscription.end_date > int(time.time()),
                        )
                        .first()
                    )

                    if existing_subscription:
                        # 如果已有订阅，延长结束日期
                        if existing_subscription.plan_id == payment.plan_id:
                            # 同一套餐，直接延长时间
                            existing_subscription.end_date = (
                                existing_subscription.end_date + 30 * 86400
                            )
                        else:
                            # 不同套餐，更新套餐并重置时间
                            existing_subscription.plan_id = payment.plan_id
                            existing_subscription.end_date = end_date

                        existing_subscription.updated_at = int(time.time())
                    else:
                        # 创建新订阅
                        subscription_id = str(uuid.uuid4())
                        new_subscription = Subscription(
                            id=subscription_id,
                            user_id=payment.user_id,
                            plan_id=payment.plan_id,
                            status="active",
                            start_date=start_date,
                            end_date=end_date,
                        )
                        db.add(new_subscription)

                db.commit()

                return {"success": True, "status": status}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_payments(
        self, user_id: Optional[str] = None, page: int = 1, limit: int = 10
    ) -> Dict[str, Any]:
        """获取支付记录列表"""
        try:
            with get_db() as db:
                query = db.query(Payment)

                if user_id:
                    query = query.filter(Payment.user_id == user_id)

                total = query.count()
                payments = (
                    query.order_by(Payment.created_at.desc())
                    .offset((page - 1) * limit)
                    .limit(limit)
                    .all()
                )

                payment_list = []
                for payment in payments:
                    payment_dict = PaymentModel.model_validate(payment).model_dump()

                    # 获取关联的套餐信息
                    plan = db.query(Plan).filter(Plan.id == payment.plan_id).first()
                    if plan:
                        payment_dict["plan_name"] = plan.name

                    payment_list.append(payment_dict)

                return {
                    "success": True,
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "payments": payment_list,
                }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_payment(self, payment_id: str) -> Dict[str, Any]:
        """获取支付记录详情"""
        try:
            with get_db() as db:
                payment = db.query(Payment).filter(Payment.id == payment_id).first()

                if not payment:
                    raise HTTPException(status_code=404, detail="支付记录不存在")

                payment_dict = PaymentModel.model_validate(payment).model_dump()

                # 获取关联的套餐信息
                plan = db.query(Plan).filter(Plan.id == payment.plan_id).first()
                if plan:
                    payment_dict["plan_name"] = plan.name

                return {"success": True, "payment": payment_dict}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


Payments = PaymentsTable()
