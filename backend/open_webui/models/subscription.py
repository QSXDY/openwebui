import time
import uuid
from decimal import Decimal
from typing import List, Tuple, Optional, Dict, Any
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
    duration = Column(BigInteger, default=30)  # 套餐持续时间（天）
    credits = Column(BigInteger, default=0)  # 套餐包含的积分数量
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


class DailyCreditGrant(Base):
    __tablename__ = "subscription_daily_credit_grants"

    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False, index=True)
    subscription_id = Column(String, ForeignKey("subscription_subscriptions.id"))
    plan_id = Column(String, ForeignKey("subscription_plans.id"))
    grant_date = Column(
        BigInteger, nullable=False, index=True
    )  # 发放日期（当天0点的时间戳）
    credits_granted = Column(BigInteger, default=0)  # 发放的积分数量
    created_at = Column(BigInteger, default=lambda: int(time.time()))


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
    plan_id = Column(String, ForeignKey("subscription_plans.id"), nullable=True)
    amount = Column(Numeric(precision=24, scale=12), default=0)
    payment_method = Column(String(50), default="lantupay")
    transaction_id = Column(String, nullable=True)
    status = Column(
        String(20), default="pending"
    )  # pending, completed, failed, refunded
    completed_at = Column(BigInteger, nullable=True)
    payment_type = Column(String(20), default="subscription")  # subscription, credits
    credits = Column(BigInteger, nullable=True)  # 如果是积分支付，购买的积分数量
    detail = Column(JSON, nullable=True)  # 支付详情，包含第三方支付平台返回的信息
    created_at = Column(BigInteger, default=lambda: int(time.time()))
    updated_at = Column(
        BigInteger, default=lambda: int(time.time()), onupdate=lambda: int(time.time())
    )


class SubscriptionCredit(Base):
    __tablename__ = "subscription_credits"

    id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False, index=True)
    subscription_id = Column(String, ForeignKey("subscription_subscriptions.id"))
    plan_id = Column(String, ForeignKey("subscription_plans.id"))
    total_credits = Column(BigInteger, default=0)  # 套餐总积分
    remaining_credits = Column(BigInteger, default=0)  # 剩余积分
    consumed_credits = Column(BigInteger, default=0)  # 已消费积分
    start_date = Column(BigInteger, nullable=False)  # 套餐开始时间
    end_date = Column(BigInteger, nullable=False)  # 套餐结束时间
    status = Column(String(20), default="active")  # active, expired, consumed
    created_at = Column(BigInteger, default=lambda: int(time.time()))
    updated_at = Column(
        BigInteger, default=lambda: int(time.time()), onupdate=lambda: int(time.time())
    )


####################
# Forms
####################


class PlanModel(BaseModel):
    id: Optional[str] = None  # 将id设为可选字段
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


class DailyCreditGrantModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    user_id: str
    subscription_id: str
    plan_id: str
    grant_date: int
    credits_granted: int
    created_at: int = Field(default_factory=lambda: int(time.time()))


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


class SubscriptionCreditModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    subscription_id: str
    plan_id: str
    total_credits: int = 0
    remaining_credits: int = 0
    consumed_credits: int = 0
    start_date: int
    end_date: int
    status: str = "active"
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
                # 先将 SQLAlchemy 对象转换为字典
                plan_dict = {
                    c.name: getattr(plan, c.name) for c in plan.__table__.columns
                }
                return PlanModel.model_validate(plan_dict)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_plan_by_id(self, plan_id: str) -> Optional[PlanModel]:
        try:
            with get_db() as db:
                plan = db.query(Plan).filter(Plan.id == plan_id).first()
                if not plan:
                    return None
                # 先将 SQLAlchemy 对象转换为字典
                plan_dict = {
                    c.name: getattr(plan, c.name) for c in plan.__table__.columns
                }
                return PlanModel.model_validate(plan_dict)
        except Exception:
            return None

    def list_active_plans(self, is_active) -> List[PlanModel]:
        try:
            with get_db() as db:
                if is_active != None:
                    plans = db.query(Plan).filter(Plan.is_active == is_active).all()
                else:
                    plans = db.query(Plan).all()
                # plans = db.query(Plan).filter(Plan.is_active == True).all()
                # 转换每个 SQLAlchemy 对象为字典
                return [
                    PlanModel.model_validate(
                        {c.name: getattr(plan, c.name) for c in plan.__table__.columns}
                    )
                    for plan in plans
                ]
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
                if not sub:
                    return None
                # 先将 SQLAlchemy 对象转换为字典
                sub_dict = {c.name: getattr(sub, c.name) for c in sub.__table__.columns}
                return SubscriptionModel.model_validate(sub_dict)
        except Exception:
            return None

    def get_user_active_subscription(self, user_id: str) -> Optional[SubscriptionModel]:
        try:
            with get_db() as db:
                sub = (
                    db.query(Subscription)
                    .filter(
                        Subscription.user_id == user_id,
                        Subscription.status == "active",
                        Subscription.end_date > int(time.time()),
                    )
                    .first()
                )
                if not sub:
                    return None
                # 先将 SQLAlchemy 对象转换为字典
                sub_dict = {c.name: getattr(sub, c.name) for c in sub.__table__.columns}
                return SubscriptionModel.model_validate(sub_dict)
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

                # 在 get_user_subscription 方法中
                if not subscription:
                    # 如果没有活跃订阅，返回免费套餐
                    free_plan = db.query(Plan).filter(Plan.id == "free").first()
                    free_plan_dict = None
                    if free_plan:
                        free_plan_dict = {
                            c.name: getattr(free_plan, c.name)
                            for c in free_plan.__table__.columns
                        }
                        free_plan_dict = PlanModel.model_validate(
                            free_plan_dict
                        ).model_dump()
                    return {
                        "success": True,
                        "subscription": {
                            "user_id": user_id,
                            "plan_id": "free",
                            "plan": free_plan_dict,
                            "status": "active",
                            "is_subscribed": False,
                        },
                    }

                # 获取套餐详情
                plan = db.query(Plan).filter(Plan.id == subscription.plan_id).first()
                plan_dict = None
                if plan:
                    plan_dict = {
                        c.name: getattr(plan, c.name) for c in plan.__table__.columns
                    }
                    plan_dict = PlanModel.model_validate(plan_dict).model_dump()

                return {
                    "success": True,
                    "subscription": {
                        "id": subscription.id,
                        "user_id": subscription.user_id,
                        "plan_id": subscription.plan_id,
                        "plan": (
                            PlanModel.model_validate(
                                {
                                    c.name: getattr(plan, c.name)
                                    for c in plan.__table__.columns
                                }
                            ).model_dump()
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
            duration_days = data.get("duration_days", 31)

            if not user_id or not plan_id:
                raise HTTPException(status_code=400, detail="用户ID和套餐ID不能为空")

            with get_db() as db:
                # 检查套餐是否存在
                plan = db.query(Plan).filter(Plan.id == plan_id).first()
                if not plan:
                    raise HTTPException(status_code=404, detail="套餐不存在")

                start_date = int(time.time())
                end_date = start_date + duration_days * 86400

                # 检查是否为续费（同一套餐的活跃订阅）
                existing_subscription = (
                    db.query(Subscription)
                    .filter(
                        Subscription.user_id == user_id,
                        Subscription.plan_id == plan_id,
                        Subscription.status == "active",
                        Subscription.end_date > int(time.time()),
                    )
                    .first()
                )

                if existing_subscription:
                    # 续费逻辑：先扣除剩余积分，再添加新积分
                    expire_result = SubscriptionCredits.expire_subscription_credits(
                        user_id, existing_subscription.id
                    )

                    # 更新订阅结束时间
                    existing_subscription.end_date = end_date
                    existing_subscription.updated_at = int(time.time())
                    subscription_id = existing_subscription.id

                    # 创建新的套餐积分记录
                    SubscriptionCredits.create_subscription_credit(
                        user_id, subscription_id, plan_id, plan.credits, duration_days
                    )

                    # 添加新的套餐积分到用户总积分
                    from open_webui.models.credits import (
                        Credits,
                        AddCreditForm,
                        SetCreditFormDetail,
                    )

                    Credits.add_credit_by_user_id(
                        AddCreditForm(
                            user_id=user_id,
                            amount=Decimal(plan.credits),
                            detail=SetCreditFormDetail(
                                desc=f"套餐续费积分发放 - 套餐: {plan.name} ({duration_days}天)",
                                api_params={
                                    "subscription_id": subscription_id,
                                    "plan_id": plan_id,
                                    "is_renewal": True,
                                    "deducted_credits": expire_result.get(
                                        "deducted_credits", 0
                                    ),
                                },
                                usage={
                                    "subscription_renewal": True,
                                    "credits_granted": plan.credits,
                                },
                            ),
                        )
                    )
                else:
                    # 新订阅
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

                    # 创建套餐积分记录
                    SubscriptionCredits.create_subscription_credit(
                        user_id, subscription_id, plan_id, plan.credits, duration_days
                    )

                    # 添加套餐积分到用户总积分
                    from open_webui.models.credits import (
                        Credits,
                        AddCreditForm,
                        SetCreditFormDetail,
                    )

                    Credits.add_credit_by_user_id(
                        AddCreditForm(
                            user_id=user_id,
                            amount=Decimal(plan.credits),
                            detail=SetCreditFormDetail(
                                desc=f"套餐订阅积分发放 - 套餐: {plan.name} ({duration_days}天)",
                                api_params={
                                    "subscription_id": subscription_id,
                                    "plan_id": plan_id,
                                    "is_new_subscription": True,
                                },
                                usage={
                                    "subscription_new": True,
                                    "credits_granted": plan.credits,
                                },
                            ),
                        )
                    )

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
                        "credits_granted": plan.credits,
                        "is_renewal": existing_subscription is not None,
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

    def get_all_active_subscriptions(self) -> List[SubscriptionModel]:
        """获取所有活跃订阅"""
        try:
            with get_db() as db:
                current_time = int(time.time())
                subscriptions = (
                    db.query(Subscription)
                    .filter(
                        Subscription.status == "active",
                        Subscription.end_date > current_time,
                    )
                    .all()
                )

                return [
                    SubscriptionModel.model_validate(
                        {c.name: getattr(sub, c.name) for c in sub.__table__.columns}
                    )
                    for sub in subscriptions
                ]
        except Exception:
            return []


Subscriptions = SubscriptionsTable()


class DailyCreditGrantsTable:
    def get_today_timestamp(self) -> int:
        """获取今天0点的时间戳"""
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        return int(today.timestamp())

    def has_granted_today(self, user_id: str, subscription_id: str) -> bool:
        """检查今天是否已经发放过积分"""
        try:
            today_timestamp = self.get_today_timestamp()
            with get_db() as db:
                grant = (
                    db.query(DailyCreditGrant)
                    .filter(
                        DailyCreditGrant.user_id == user_id,
                        DailyCreditGrant.subscription_id == subscription_id,
                        DailyCreditGrant.grant_date == today_timestamp,
                    )
                    .first()
                )
                return grant is not None
        except Exception:
            return False

    def grant_daily_credits(
        self, user_id: str, subscription_id: str, plan_id: str, credits_amount: int
    ) -> Optional[DailyCreditGrantModel]:
        """发放每日积分"""
        try:
            # 检查今天是否已经发放过
            if self.has_granted_today(user_id, subscription_id):
                return None

            today_timestamp = self.get_today_timestamp()

            with get_db() as db:
                # 创建积分发放记录
                grant_id = str(uuid.uuid4())
                grant = DailyCreditGrant(
                    id=grant_id,
                    user_id=user_id,
                    subscription_id=subscription_id,
                    plan_id=plan_id,
                    grant_date=today_timestamp,
                    credits_granted=credits_amount,
                )
                db.add(grant)

                # 给用户添加积分
                from open_webui.models.credits import (
                    Credits,
                    AddCreditForm,
                    SetCreditFormDetail,
                )

                Credits.add_credit_by_user_id(
                    AddCreditForm(
                        user_id=user_id,
                        amount=Decimal(credits_amount),
                        detail=SetCreditFormDetail(
                            desc=f"每日套餐积分发放 - 套餐ID: {plan_id}",
                            api_params={
                                "subscription_id": subscription_id,
                                "plan_id": plan_id,
                            },
                            usage={"daily_grant": credits_amount},
                        ),
                    )
                )

                db.commit()
                db.refresh(grant)

                return DailyCreditGrantModel.model_validate(
                    {c.name: getattr(grant, c.name) for c in grant.__table__.columns}
                )
        except Exception as e:
            print(f"发放每日积分失败: {str(e)}")
            return None

    def process_daily_grants_for_all_users(self) -> Dict[str, Any]:
        """为所有活跃订阅用户发放每日积分"""
        try:
            successful_grants = 0
            failed_grants = 0

            # 获取所有活跃订阅
            active_subscriptions = Subscriptions.get_all_active_subscriptions()

            for subscription in active_subscriptions:
                # 获取套餐信息
                plan = Plans.get_plan_by_id(subscription.plan_id)
                if not plan or plan.credits <= 0:
                    continue

                # 尝试发放积分
                grant = self.grant_daily_credits(
                    user_id=subscription.user_id,
                    subscription_id=subscription.id,
                    plan_id=subscription.plan_id,
                    credits_amount=plan.credits,
                )

                if grant:
                    successful_grants += 1
                else:
                    failed_grants += 1

            return {
                "success": True,
                "total_subscriptions": len(active_subscriptions),
                "successful_grants": successful_grants,
                "failed_grants": failed_grants,
                "message": f"处理完成: 成功发放 {successful_grants} 个用户的积分",
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "message": "每日积分发放处理失败",
            }

    def get_user_grant_history(
        self, user_id: str, page: int = 1, limit: int = 10
    ) -> Dict[str, Any]:
        """获取用户积分发放历史"""
        try:
            with get_db() as db:
                total = (
                    db.query(DailyCreditGrant)
                    .filter(DailyCreditGrant.user_id == user_id)
                    .count()
                )

                grants = (
                    db.query(DailyCreditGrant)
                    .filter(DailyCreditGrant.user_id == user_id)
                    .order_by(DailyCreditGrant.grant_date.desc())
                    .offset((page - 1) * limit)
                    .limit(limit)
                    .all()
                )

                return {
                    "success": True,
                    "total": total,
                    "page": page,
                    "limit": limit,
                    "grants": [
                        DailyCreditGrantModel.model_validate(
                            {
                                c.name: getattr(grant, c.name)
                                for c in grant.__table__.columns
                            }
                        ).model_dump()
                        for grant in grants
                    ],
                }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))


DailyCreditGrants = DailyCreditGrantsTable()


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

    def redeem_code(self, code: str, user_id: str) -> tuple:
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
                    return None, "兑换码不存在、已被使用或已过期"

                plan = db.query(Plan).filter(Plan.id == redeem_code.plan_id).first()
                if not plan:
                    return None, "关联的套餐不存在"

                start_date = int(time.time())
                end_date = start_date + redeem_code.duration_days * 86400

                subscription = Subscription(
                    id=str(uuid.uuid4().hex),  # 添加这一行生成唯一ID
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
                return SubscriptionModel.model_validate(subscription), "兑换成功"
        except Exception as e:
            return None, f"处理异常: {str(e)}"

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
    def create_payment_order(self, payment_data: Dict[str, Any]) -> Dict[str, Any]:
        """创建支付订单"""
        try:
            user_id = payment_data.get("user_id")
            plan_id = payment_data.get("plan_id")
            payment_method = payment_data.get("payment_method", "lantupay")

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

    def create_payment(self, payment_data: Dict[str, Any]) -> Optional[PaymentModel]:
        """创建支付记录"""
        try:
            with get_db() as db:
                # 确保有ID
                if "id" not in payment_data:
                    payment_data["id"] = str(uuid.uuid4())

                # 创建支付记录
                payment = Payment(**payment_data)
                db.add(payment)
                db.commit()
                db.refresh(payment)
                return PaymentModel.model_validate(payment)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def update_payment(
        self, payment_id: str, payment_data: PaymentModel
    ) -> Optional[PaymentModel]:
        """更新支付记录"""
        try:
            with get_db() as db:
                # 更新支付记录
                db.query(Payment).filter(Payment.id == payment_id).update(
                    payment_data.model_dump(exclude_unset=True),
                    synchronize_session=False,
                )
                db.commit()
                # 返回更新后的记录
                payment = db.query(Payment).filter(Payment.id == payment_id).first()
                return PaymentModel.model_validate(payment) if payment else None
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    def get_payment(self, payment_id: str) -> Optional[PaymentModel]:
        """获取支付记录"""
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
                return self.get_payment(payment_id)
        except Exception:
            return None

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

    def get_payment_detail(self, payment_id: str) -> Dict[str, Any]:
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


class SubscriptionCreditsTable:
    def create_subscription_credit(
        self,
        user_id: str,
        subscription_id: str,
        plan_id: str,
        credits: int,
        duration_days: int = 31,
    ) -> Optional[SubscriptionCreditModel]:
        """创建套餐积分记录"""
        try:
            start_date = int(time.time())
            end_date = start_date + duration_days * 86400

            with get_db() as db:
                subscription_credit = SubscriptionCredit(
                    id=str(uuid.uuid4()),
                    user_id=user_id,
                    subscription_id=subscription_id,
                    plan_id=plan_id,
                    total_credits=credits,
                    remaining_credits=credits,
                    consumed_credits=0,
                    start_date=start_date,
                    end_date=end_date,
                    status="active",
                )
                db.add(subscription_credit)
                db.commit()
                db.refresh(subscription_credit)

                return SubscriptionCreditModel.model_validate(
                    {
                        c.name: getattr(subscription_credit, c.name)
                        for c in subscription_credit.__table__.columns
                    }
                )
        except Exception as e:
            print(f"创建套餐积分记录失败: {str(e)}")
            return None

    def get_user_active_subscription_credits(
        self, user_id: str
    ) -> List[SubscriptionCreditModel]:
        """获取用户所有活跃的套餐积分记录，按创建时间排序"""
        try:
            with get_db() as db:
                credits = (
                    db.query(SubscriptionCredit)
                    .filter(
                        SubscriptionCredit.user_id == user_id,
                        SubscriptionCredit.status == "active",
                        SubscriptionCredit.remaining_credits > 0,
                    )
                    .order_by(
                        SubscriptionCredit.created_at.asc()
                    )  # 按创建时间升序，优先消费早期套餐
                    .all()
                )

                return [
                    SubscriptionCreditModel.model_validate(
                        {
                            c.name: getattr(credit, c.name)
                            for c in credit.__table__.columns
                        }
                    )
                    for credit in credits
                ]
        except Exception:
            return []

    def consume_subscription_credits(self, user_id: str, amount: int) -> Dict[str, Any]:
        """消费套餐积分，按时间顺序优先消费早期套餐"""
        try:
            remaining_amount = amount
            consumed_records = []

            with get_db() as db:
                # 获取用户所有可用的套餐积分，按创建时间排序
                subscription_credits = (
                    db.query(SubscriptionCredit)
                    .filter(
                        SubscriptionCredit.user_id == user_id,
                        SubscriptionCredit.status == "active",
                        SubscriptionCredit.remaining_credits > 0,
                    )
                    .order_by(SubscriptionCredit.created_at.asc())
                    .all()
                )

                for sub_credit in subscription_credits:
                    if remaining_amount <= 0:
                        break

                    # 计算本次消费金额
                    consume_amount = min(sub_credit.remaining_credits, remaining_amount)

                    # 更新套餐积分记录
                    sub_credit.remaining_credits -= consume_amount
                    sub_credit.consumed_credits += consume_amount

                    # 如果积分用完，标记为已消费
                    if sub_credit.remaining_credits <= 0:
                        sub_credit.status = "consumed"

                    sub_credit.updated_at = int(time.time())

                    consumed_records.append(
                        {
                            "subscription_id": sub_credit.subscription_id,
                            "plan_id": sub_credit.plan_id,
                            "consumed": consume_amount,
                            "remaining": sub_credit.remaining_credits,
                        }
                    )

                    remaining_amount -= consume_amount

                db.commit()

                return {
                    "success": True,
                    "total_consumed": amount - remaining_amount,
                    "remaining_amount": remaining_amount,
                    "consumed_records": consumed_records,
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "total_consumed": 0,
                "remaining_amount": amount,
            }

    def expire_subscription_credits(
        self, user_id: str, subscription_id: str
    ) -> Dict[str, Any]:
        """套餐过期处理，扣除剩余积分"""
        try:
            with get_db() as db:
                # 获取该订阅的积分记录
                sub_credit = (
                    db.query(SubscriptionCredit)
                    .filter(
                        SubscriptionCredit.user_id == user_id,
                        SubscriptionCredit.subscription_id == subscription_id,
                        SubscriptionCredit.status == "active",
                    )
                    .first()
                )

                if not sub_credit:
                    return {"success": True, "deducted_credits": 0}

                deducted_credits = sub_credit.remaining_credits

                if deducted_credits > 0:
                    # 从用户总积分中扣除剩余的套餐积分
                    from open_webui.models.credits import (
                        Credits,
                        AddCreditForm,
                        SetCreditFormDetail,
                    )

                    Credits.add_credit_by_user_id(
                        AddCreditForm(
                            user_id=user_id,
                            amount=Decimal(-deducted_credits),
                            detail=SetCreditFormDetail(
                                desc=f"套餐过期扣除剩余积分: -{deducted_credits}",
                                api_params={
                                    "subscription_id": subscription_id,
                                    "plan_id": sub_credit.plan_id,
                                    "expired_credits": deducted_credits,
                                },
                                usage={"subscription_expired": True},
                            ),
                        )
                    )

                # 标记套餐积分为过期
                sub_credit.status = "expired"
                sub_credit.updated_at = int(time.time())
                db.commit()

                return {
                    "success": True,
                    "deducted_credits": deducted_credits,
                    "subscription_id": subscription_id,
                }
        except Exception as e:
            return {"success": False, "error": str(e), "deducted_credits": 0}

    def check_and_expire_subscriptions(self) -> Dict[str, Any]:
        """检查并处理过期的套餐"""
        try:
            current_time = int(time.time())
            expired_count = 0
            total_deducted = 0

            with get_db() as db:
                # 获取所有过期的套餐积分记录
                expired_credits = (
                    db.query(SubscriptionCredit)
                    .filter(
                        SubscriptionCredit.status == "active",
                        SubscriptionCredit.end_date <= current_time,
                    )
                    .all()
                )

                for sub_credit in expired_credits:
                    result = self.expire_subscription_credits(
                        sub_credit.user_id, sub_credit.subscription_id
                    )
                    if result["success"]:
                        expired_count += 1
                        total_deducted += result["deducted_credits"]

                return {
                    "success": True,
                    "expired_count": expired_count,
                    "total_deducted_credits": total_deducted,
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "expired_count": 0,
                "total_deducted_credits": 0,
            }

    def get_total_active_credits(self, user_id: str) -> int:
        """获取用户所有活跃套餐的总积分"""
        try:
            with get_db() as db:
                current_time = int(time.time())
                active_credits = (
                    db.query(SubscriptionCredit)
                    .filter(
                        SubscriptionCredit.user_id == user_id,
                        SubscriptionCredit.status == "active",
                        SubscriptionCredit.end_date > current_time,
                        SubscriptionCredit.remaining_credits > 0,
                    )
                    .all()
                )

                total_credits = sum(
                    credit.remaining_credits for credit in active_credits
                )
                return total_credits
        except Exception as e:
            print(f"Error getting total active credits: {e}")
            return 0


SubscriptionCredits = SubscriptionCreditsTable()
