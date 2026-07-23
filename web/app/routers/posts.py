from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import delete, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.common.auth import get_current_user
from app.core.database import get_db
from app.models.comment import Comment
from app.models.post import Post
from app.models.user import User

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")

router = APIRouter()


@router.get("/posts")
def posts_list(
    request: Request,
    keyword: str | None = None,
    db: Session = Depends(get_db),
):
    if keyword:
        # 검색창에서 SQL injection을 재현하기 위해 문자열 조합을 남겨 둔다.
        query = (
            "SELECT posts.id, posts.title, posts.content, posts.is_private, posts.created_at, "
            "users.nickname AS author FROM posts "
            "JOIN users ON posts.user_id = users.id "
            f"WHERE posts.is_private = false AND (title LIKE '%{keyword}%' "
            f"OR content LIKE '%{keyword}%') "
            "ORDER BY posts.id DESC"
        )
        try:
            posts = db.execute(text(query)).mappings().all()
        except SQLAlchemyError:
            # SQL 문법을 깨는 XSS 문자열도 응답 화면까지 도달하도록 빈 결과로 처리한다.
            # 공격 입력은 별도 보안 이벤트로 기록하지 않는 A09 실습 상태를 유지한다.
            db.rollback()
            posts = []
    else:
        posts = db.execute(
            select(
                Post.id,
                Post.title,
                Post.content,
                Post.is_private,
                Post.created_at,
                User.nickname.label("author"),
            )
            .join(User, Post.user_id == User.id)
            .where(Post.is_private.is_(False))
            .order_by(Post.id.desc())
        ).all()

    return templates.TemplateResponse(
        request,
        "posts.html",
        {"posts": posts, "user": get_current_user(request, db), "keyword": keyword or ""},
    )


@router.get("/posts/new")
def new_post_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(request, "post_new.html", {"user": user})


@router.post("/posts/new")
def create_post(
    request: Request,
    title: str = Form(...),
    content: str = Form(...),
    is_private: bool = Form(False),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=401, detail="Login required")

    post = Post(user_id=user.id, title=title, content=content, is_private=is_private)
    db.add(post)
    db.commit()
    target = "/posts/mine" if is_private else f"/posts/{post.id}"
    return RedirectResponse(url=target, status_code=303)


@router.get("/posts/mine")
def my_posts(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)

    posts = db.execute(
        select(Post.id, Post.title, Post.is_private, Post.created_at)
        .where(Post.user_id == user.id)
        .order_by(Post.id.desc())
    ).all()
    return templates.TemplateResponse(
        request,
        "my_posts.html",
        {"user": user, "posts": posts},
    )


@router.get("/posts/{post_id}")
def post_detail(request: Request, post_id: int, db: Session = Depends(get_db)):
    post = db.execute(
        select(
            Post.id, Post.title, Post.content, Post.created_at, User.nickname.label("author")
        )
        .join(User, Post.user_id == User.id)
        .where(Post.id == post_id, Post.is_private.is_(False))
    ).first()
    comments = db.execute(
        select(Comment.id, Comment.content, User.nickname.label("author"))
        .join(User, Comment.user_id == User.id)
        .where(Comment.post_id == post_id)
        .order_by(Comment.id.desc())
    ).all()

    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")

    return templates.TemplateResponse(
        request,
        "post_detail.html",
        {"post": post, "comments": comments, "user": get_current_user(request, db)},
    )


@router.get("/posts/private/{post_id}")
def private_post(request: Request, post_id: int, db: Session = Depends(get_db)):
    post = db.execute(
        select(
            Post.id, Post.title, Post.content, Post.created_at, User.nickname.label("author")
        )
        .join(User, Post.user_id == User.id)
        .where(Post.id == post_id)
    ).first()

    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")

    # TODO(lab): 작성자 검증이 빠져 있음 - IDOR 실습용
    current_user = get_current_user(request, db)
    if current_user is None:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse(
        request,
        "private_post.html",
        {"post": post, "user": current_user},
    )


@router.post("/posts/{post_id}/delete")
def delete_post(request: Request, post_id: int, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if current_user is None:
        return RedirectResponse(url="/login", status_code=303)

    # 권한 확인은 접근 제어 실습을 위해 일부러 누락한 상태다.
    db.execute(delete(Comment).where(Comment.post_id == post_id))
    db.execute(delete(Post).where(Post.id == post_id))
    db.commit()
    return RedirectResponse(url="/admin", status_code=303)
