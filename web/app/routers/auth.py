from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")

router = APIRouter()


@router.get("/register")
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"user": None})


@router.post("/register")
def register_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    nickname: str = Form(...),
    db: Session = Depends(get_db),
):
    # 실습을 위해 비밀번호 복잡도 정책을 적용하지 않았습니다.
    # 운영 환경에서는 최소 길이, 복잡도, 유출 비밀번호 차단 정책이 필요합니다.
    try:
        db.add(User(username=username, password=password, nickname=nickname, role="user"))
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Username already exists")

    return RedirectResponse(url="/login", status_code=303)


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None, "user": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    # SQL injection 실습 포인트. 수정 버전에서는 placeholder로 바꾸기.
    # 실습을 위해 로그인 실패 횟수 제한, 지연, CAPTCHA, 계정 잠금을 적용하지 않습니다.
    # 반복 실패나 Injection 시도 또한 별도 보안 이벤트로 기록하지 않습니다.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = db.execute(text(query)).mappings().first()

    if user is None:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid username or password", "user": None},
        )

    request.session["user_id"] = user["id"]
    request.session["username"] = user["username"]
    request.session["role"] = user["role"]
    return RedirectResponse(url="/posts", status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)
