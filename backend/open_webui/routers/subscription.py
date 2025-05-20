from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Body,
    Query,
    Path,
    Request,
    status,
)
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime
from decimal import Decimal

# 导入模型和工具
from open_webui.models.subscription import (
    Plans,
    Subscriptions,
    RedeemCodes,
    Payments,
    PlanModel,
    SubscriptionModel,
    RedeemCodeModel,
    PaymentModel,
)
from open_webui.models.users import UserModel
from open_webui.utils.auth import get_current_user, get_admin_user
from open_webui.utils.payment import create_payment

router = APIRouter()

# ============== 套餐管理接口 ==============


@router.get(
    "/plans",
    response_model=Dict[str, Any],
    summary="获取所有套餐",
    description="获取所有可用的订阅套餐列表（仅返回活跃套餐）",
)
async def list_plans():
    """获取所有活跃套餐"""
    # 实现同前...


@router.post("/plans", status_code=status.HTTP_201_CREATED, summary="创建新套餐")
async def create_plan(
    plan_data: PlanModel = Body(...), _: UserModel = Depends(get_admin_user)
):
    """创建新套餐（管理员权限）"""
    # 实现同前...


@router.put(
    "/plans/{plan_id}",
    summary="更新套餐信息",
    responses={
        403: {"description": "需要管理员权限"},
        404: {"description": "套餐不存在"},
    },
)
async def update_plan(
    plan_id: str = Path(..., description="套餐ID"),
    plan_data: Dict[str, Any] = Body(...),
    _: UserModel = Depends(get_admin_user),
):
    """更新套餐信息"""
    try:
        updated_plan = Plans.update_plan(plan_id, PlanModel(**plan_data))
        return {
            "success": True,
            "data": updated_plan.model_dump(),
            "message": "套餐更新成功",
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"更新失败: {str(e)}",
        )


@router.delete(
    "/plans/{plan_id}",
    summary="删除套餐",
    responses={
        403: {"description": "需要管理员权限"},
        404: {"description": "套餐不存在"},
    },
)
async def delete_plan(plan_id: str = Path(...), _: UserModel = Depends(get_admin_user)):
    """删除套餐（自动处理关联订阅）"""
    return Plans.delete_plan(plan_id)


# ============== 用户订阅接口 ==============


@router.get("/users/{user_id}/subscription", summary="获取用户订阅详情")
async def get_user_subscription(
    user_id: str, user: UserModel = Depends(get_current_user)
):
    """获取用户当前订阅状态"""
    # 实现同前...


@router.post(
    "/subscriptions/purchase",
    status_code=status.HTTP_201_CREATED,
    summary="购买订阅套餐",
)
async def purchase_subscription(
    request: Request,
    plan_id: str = Body(..., embed=True),
    user: UserModel = Depends(get_current_user),
):
    """发起套餐购买（生成支付订单）"""
    try:
        plan = Plans.get_plan_by_id(plan_id)
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="套餐不存在"
            )

        return await create_payment(
            request=request,
            user=user,
            payment_type="subscription",
            amount=plan.price,
            plan_id=plan_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"购买失败: {str(e)}",
        )


@router.post(
    "/subscriptions/cancel",
    summary="取消订阅",
    responses={
        400: {"description": "无效的订阅ID"},
        403: {"description": "只能取消自己的订阅"},
    },
)
async def cancel_subscription(
    subscription_id: str = Body(..., embed=True),
    user: UserModel = Depends(get_current_user),
):
    """取消用户订阅"""
    try:
        subscription = Subscriptions.get_subscription_by_id(subscription_id)
        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="订阅不存在"
            )

        if subscription.user_id != user.id and user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="无权操作他人订阅"
            )

        return Subscriptions.cancel_subscription({"subscription_id": subscription_id})
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"取消失败: {str(e)}",
        )


# ============== 兑换码接口 ==============


@router.get(
    "/redeem-codes",
    summary="获取兑换码列表",
    description="分页获取兑换码列表（管理员权限）",
)
async def list_redeem_codes(
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    _: UserModel = Depends(get_admin_user),
):
    """获取兑换码列表（分页）"""
    return RedeemCodes.get_redeem_codes(page, limit)


@router.post(
    "/redeem-codes", status_code=status.HTTP_201_CREATED, summary="批量生成兑换码"
)
async def generate_redeem_codes(
    plan_id: str = Body(...),
    count: int = Body(1, ge=1, le=100),
    duration_days: int = Body(30, ge=1),
    _: UserModel = Depends(get_admin_user),
):
    """生成指定数量的兑换码"""
    try:
        result = RedeemCodes.create_redeem_codes(
            {"plan_id": plan_id, "count": count, "duration_days": duration_days}
        )
        return {"success": True, "data": result, "message": f"成功生成{count}个兑换码"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"生成失败: {str(e)}",
        )


@router.post(
    "/redeem",
    status_code=status.HTTP_200_OK,
    summary="兑换订阅码",
    responses={
        400: {"description": "兑换码无效或已使用"},
        403: {"description": "需要登录后才能兑换"},
    },
)
async def redeem_code(
    redeem_data: Dict[str, str] = Body(..., example={"code": "ABCD-EFGH"}),
    user: UserModel = Depends(get_current_user),
):
    """
    使用兑换码激活订阅
    - code: 兑换码字符串（必填）
    - 成功兑换后自动延长用户订阅有效期
    """
    try:
        code = redeem_data.get("code")
        if not code or len(code) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="兑换码格式无效"
            )

        # 调用业务逻辑
        subscription = RedeemCodes.redeem_code(code, user.id)
        if not subscription:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="兑换码无效或已使用"
            )

        return {
            "success": True,
            "data": {
                "subscription": subscription.model_dump(),
                "new_expiry": datetime.fromtimestamp(subscription.end_date).isoformat(),
            },
            "message": "兑换成功",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"兑换失败: {str(e)}",
        )


# ============== 支付记录接口 ==============


@router.get("/payments/{payment_id}", summary="获取支付记录详情")
async def get_payment_detail(
    payment_id: str, user: UserModel = Depends(get_current_user)
):
    """查看支付订单详情"""
    try:
        payment = Payments.get_payment(payment_id)
        if not payment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="支付记录不存在"
            )

        if payment.user_id != user.id and user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="无权查看此支付记录"
            )

        return {
            "success": True,
            "data": payment,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取失败: {str(e)}",
        )


@router.get(
    "/payments/{payment_id}",
    summary="获取支付记录详情",
    responses={
        403: {"description": "无权查看他人支付记录"},
        404: {"description": "支付记录不存在"},
    },
)
async def get_payment_detail(
    payment_id: str = Path(..., description="支付订单ID"),
    user: UserModel = Depends(get_current_user),
):
    """获取指定支付订单的详细信息（包含关联套餐信息）"""
    try:
        payment = Payments.get_payment(payment_id)
        if not payment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="支付记录不存在"
            )

        # 权限验证
        if payment.user_id != user.id and user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="无权查看此支付记录"
            )

        # 获取关联套餐信息
        plan = Plans.get_plan_by_id(payment.plan_id) if payment.plan_id else None

        return {
            "success": True,
            "data": {
                "payment": payment.model_dump(),
                "plan": plan.model_dump() if plan else None,
            },
            "timestamp": datetime.now().isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"获取支付详情失败: {str(e)}",
        )


def add_api_routes(app):
    """注册所有订阅系统路由"""
    app.include_router(router)
