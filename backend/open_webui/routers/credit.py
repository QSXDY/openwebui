import datetime
import logging
import uuid
from collections import defaultdict
from decimal import Decimal
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from pydantic import BaseModel

from open_webui.config import EZFP_CALLBACK_HOST
from open_webui.env import SRC_LOG_LEVELS
from open_webui.models.credits import (
    TradeTicketModel,
    TradeTickets,
    CreditLogSimpleModel,
    CreditLogs,
)
from open_webui.models.models import Models, ModelPriceForm
from open_webui.models.users import UserModel, Users
from open_webui.utils.auth import get_current_user, get_admin_user
from open_webui.utils.credit.ezfp import ezfp_client
from open_webui.utils.models import get_all_models

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MAIN"])

router = APIRouter()


@router.get("/config")
async def get_config(request: Request):
    return {
        "CREDIT_EXCHANGE_RATIO": request.app.state.config.CREDIT_EXCHANGE_RATIO,
        "EZFP_PAY_PRIORITY": request.app.state.config.EZFP_PAY_PRIORITY,
    }


@router.get("/logs", response_model=list[CreditLogSimpleModel])
async def list_credit_logs(
    page: Optional[int] = None, user: UserModel = Depends(get_current_user)
) -> TradeTicketModel:
    if page:
        limit = 10
        offset = (page - 1) * limit
        return CreditLogs.get_credit_log_by_page(
            user_id=user.id, offset=offset, limit=limit
        )
    else:
        return CreditLogs.get_credit_log_by_page(user_id=user.id, offset=0, limit=10)


@router.get("/all_logs")
async def get_all_logs(
    user_id: Optional[str] = None,
    page: Optional[int] = None,
    limit: Optional[int] = None,
    _: UserModel = Depends(get_admin_user),
):
    page = page or 1
    limit = limit or 10
    offset = (page - 1) * limit
    results = CreditLogs.get_credit_log_by_page(
        user_id=user_id, offset=offset, limit=limit
    )
    total = CreditLogs.count_credit_log(user_id=user_id)
    users = Users.get_users()
    user_map = {user.id: user.name for user in users["users"]}
    for result in results:
        setattr(result, "username", user_map.get(result.user_id, ""))
    return {"total": total, "results": results}


@router.post("/tickets", response_model=TradeTicketModel)
async def create_ticket(
    request: Request, form_data: dict, user: UserModel = Depends(get_current_user)
) -> TradeTicketModel:
    out_trade_no = (
        f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.{uuid.uuid4().hex}"
    )
    return TradeTickets.insert_new_ticket(
        id=out_trade_no,
        user_id=user.id,
        amount=form_data["amount"],
        detail=await ezfp_client.create_trade(
            pay_type=form_data["pay_type"],
            out_trade_no=out_trade_no,
            amount=form_data["amount"],
            client_ip=request.client.host,
            ua=request.headers.get("User-Agent"),
        ),
    )


@router.get("/callback", response_class=PlainTextResponse)
async def ticket_callback(request: Request) -> str:
    callback = dict(request.query_params)
    if not ezfp_client.verify(callback):
        return "invalid signature"

    # payment failed
    if callback["trade_status"] != "TRADE_SUCCESS":
        return "success"

    # find ticket
    ticket = TradeTickets.get_ticket_by_id(callback["out_trade_no"])
    if not ticket:
        return "no ticket fount"

    # already callback
    if ticket.detail.get("callback"):
        return "success"

    ticket.detail["callback"] = callback
    TradeTickets.update_credit_by_id(ticket.id, ticket.detail)

    return "success"


@router.get("/callback/redirect", response_class=RedirectResponse)
async def ticket_callback_redirect() -> RedirectResponse:
    return RedirectResponse(url=EZFP_CALLBACK_HOST.value, status_code=302)


@router.get("/models/price")
async def get_model_price(request: Request, user: UserModel = Depends(get_admin_user)):
    # no info means not saved in db, which cannot be updated
    # preset model is always using base model's price
    return {
        model["id"]: model.get("info", {}).get("price") or {}
        for model in await get_all_models(request, user)
        if model.get("info") and not model.get("info", {}).get("base_model_id")
    }


@router.put("/models/price")
async def update_model_price(
    form_data: dict[str, dict], _: UserModel = Depends(get_admin_user)
):
    for model_id, price in form_data.items():
        model = Models.get_model_by_id(id=model_id)
        if not model:
            continue
        model.price = (
            ModelPriceForm.model_validate(price).model_dump() if price else None
        )
        Models.update_model_by_id(id=model_id, model=model)
    return f"success update price for {len(form_data)} models"


class StatisticRequest(BaseModel):
    start_time: int
    end_time: int


@router.post("/statistics")
async def get_statistics(
    form_data: StatisticRequest, _: UserModel = Depends(get_admin_user)
):
    # load credit data
    logs = CreditLogs.get_log_by_time(form_data.start_time, form_data.end_time)
    trade_logs = TradeTickets.get_ticket_by_time(
        form_data.start_time, form_data.end_time
    )

    # load user data
    users = Users.get_users()["users"]
    user_map = {user.id: user.name for user in users}

    # build graph data
    model_cost_pie = defaultdict(int)
    model_token_pie = defaultdict(int)
    user_cost_pie = defaultdict(int)
    user_token_pie = defaultdict(int)
    for log in logs:
        if not log.detail.usage or log.detail.usage.total_price is None:
            continue

        model = log.detail.api_params.model
        if not model:
            continue

        model_key = log.detail.api_params.model.id
        model_cost_pie[model_key] += log.detail.usage.total_price
        model_token_pie[model_key] += log.detail.usage.total_tokens

        user_key = f"{log.user_id}:{user_map.get(log.user_id, log.user_id)}"
        user_cost_pie[user_key] += log.detail.usage.total_price
        user_token_pie[user_key] += log.detail.usage.total_tokens

    # build trade data
    user_payment_data = defaultdict(Decimal)
    for log in trade_logs:
        callback = log.detail.get("callback")
        if not callback:
            continue
        if callback.get("trade_status") != "TRADE_SUCCESS":
            continue
        time_key = datetime.datetime.fromtimestamp(log.created_at).strftime("%Y-%m-%d")
        user_payment_data[time_key] += log.amount
    user_payment_stats_x = []
    user_payment_stats_y = []
    for key, val in user_payment_data.items():
        user_payment_stats_x.append(key)
        user_payment_stats_y.append(val)

    # response
    return {
        "model_cost_pie": [
            {"name": model, "value": total} for model, total in model_cost_pie.items()
        ],
        "model_token_pie": [
            {"name": model, "value": total} for model, total in model_token_pie.items()
        ],
        "user_cost_pie": [
            {"name": user.split(":", 1)[1], "value": total}
            for user, total in user_cost_pie.items()
        ],
        "user_token_pie": [
            {"name": user.split(":", 1)[1], "value": total}
            for user, total in user_token_pie.items()
        ],
        "user_payment_stats_x": user_payment_stats_x,
        "user_payment_stats_y": user_payment_stats_y,
    }
