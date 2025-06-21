from fastapi import FastAPI, Request, Depends
from urllib.parse import quote
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import requests
import uuid
import time
from typing import Dict

app = FastAPI()

# 配置信息 - 替换为你的实际信息
WECHAT_APPID = "wx17a96b510ddfb2a5"
WECHAT_SECRET = "e282c9363d87085f2d9f14cbb72c45c4"
REDIRECT_URI = "http://yb748266.natappfree.cc/callback"  # 你的natapp地址
TOKEN = "wechat123"  # 与微信测试号配置的Token一致
DOMAIN = "yb748266.natappfree.cc"  # 你的natapp域名

# 存储临时状态和用户信息
state_store: Dict[str, dict] = {}
user_store: Dict[str, dict] = {}

# 挂载静态文件
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.get("/")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/login")
async def wechat_login():
    state = str(uuid.uuid4())
    state_store[state] = {"created_at": time.time()}

    # 使用网页授权URL但伪装成扫码登录页面
    auth_url = (
        f"https://open.weixin.qq.com/connect/oauth2/authorize?"
        f"appid={WECHAT_APPID}"
        f"&redirect_uri={quote(REDIRECT_URI, safe='')}"
        f"&response_type=code"
        f"&scope=snsapi_userinfo"
        f"&state={state}"
        f"#wechat_redirect"
    )

    # 返回一个包含iframe的页面模拟扫码效果
    return HTMLResponse(
        f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>微信登录</title>
        <style>
            .qrcode-container {{
                width: 300px;
                margin: 50px auto;
                text-align: center;
            }}
            iframe {{
                border: none;
                width: 300px;
                height: 300px;
            }}
        </style>
    </head>
    <body>
        <div class="qrcode-container">
            <h3>微信扫码登录</h3>
            <iframe src="{auth_url}"></iframe>
            <p>请在弹出的页面中授权</p>
        </div>
    </body>
    </html>
    """
    )


@app.get("/callback")
async def wechat_verify(
    signature: str = None,
    timestamp: str = None,
    nonce: str = None,
    echostr: str = None,
    code: str = None,  # 授权回调会带code
    state: str = None,  # 授权回调会带state
):
    # 处理微信服务器验证
    if echostr:
        # 1. 验证签名（简化版，生产环境需要完整验证）
        tmp_list = [TOKEN, timestamp, nonce]
        tmp_list.sort()
        tmp_str = "".join(tmp_list).encode("utf-8")
        import hashlib

        hashcode = hashlib.sha1(tmp_str).hexdigest()

        if hashcode == signature:
            return HTMLResponse(content=echostr)
        else:
            return HTMLResponse(content="验证失败", status_code=403)

    # 2. 处理授权回调（用户扫码登录后的跳转）
    if code and state:
        # 这里放你原来的授权回调处理代码
        # ...
        return RedirectResponse(url="/welcome")

    return {"error": "invalid request"}


@app.get("/welcome")
async def welcome(request: Request):
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in user_store:
        return RedirectResponse(url="/")

    user_info = user_store[session_id]
    return templates.TemplateResponse(
        "welcome.html",
        {
            "request": request,
            "nickname": user_info.get("nickname", ""),
            "avatar": user_info.get("headimgurl", ""),
        },
    )


# 微信服务器验证接口
@app.get("/wechat")
async def wechat_verify(signature: str, timestamp: str, nonce: str, echostr: str):
    # 这里应该实现签名验证，为了简化示例，我们直接返回echostr
    return HTMLResponse(content=echostr)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
