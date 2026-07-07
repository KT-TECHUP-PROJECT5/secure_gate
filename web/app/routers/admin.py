from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common.auth import get_current_user
from app.core.database import get_db
from app.models.comment import Comment
from app.models.post import Post
from app.models.user import User

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")

router = APIRouter()


@router.get("/admin")
def admin_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None:
        return templates.TemplateResponse(request, "login.html", {"error": None, "user": None})

    # role 검사 없음: 일반 계정으로 관리자 화면 접근을 확인하는 실습 구간
    users = db.scalars(select(User).order_by(User.id)).all()
    posts = db.execute(
        select(Post.id, Post.title, User.nickname.label("author"))
        .join(User, Post.user_id == User.id)
        .order_by(Post.id)
    ).all()
    comments = db.execute(
        select(Comment.id, Comment.post_id, User.nickname.label("author"), Comment.content)
        .join(User, Comment.user_id == User.id)
        .order_by(Comment.id)
    ).all()

    return templates.TemplateResponse(
        request,
        "admin.html",
        {"user": user, "users": users, "posts": posts, "comments": comments},
    )


@router.get("/admin/security-events")
def security_events_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None:
        return templates.TemplateResponse(request, "login.html", {"error": None, "user": None})

    # 기존 관리자 화면처럼 role 검사를 하지 않는 취약한 접근 제어를 유지합니다.
    # 실습을 위해 보안 이벤트 로깅과 알림을 구현하지 않았습니다.
    # 운영 환경에서는 인증 실패, 권한 위반, Injection 시도, 악성 업로드 등을
    # 보안 이벤트로 기록하고 알림 연동이 필요합니다.
    security_events: list[dict] = []
    return templates.TemplateResponse(
        request,
        "security_events.html",
        {"user": user, "security_events": security_events},
    )
