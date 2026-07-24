from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.database import get_db

BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")

router = APIRouter()


@router.get("/debug")
def debug_page(request: Request):
    return templates.TemplateResponse(
        request,
        "error_debug.html",
        {
            "user": None,
            "error_type": "DebugIndex",
            "error_message": "실습할 오류 경로를 선택하세요.",
            "internal_hint": "/debug/error, /debug/db-error, /debug/path-error",
        },
    )


@router.get("/debug/error")
def general_error(request: Request):
    try:
        raise Exception("Intentional debug error from app/routers/errors.py")
    except Exception as exc:
        # 실습을 위해 예외 메시지와 내부 정보를 사용자에게 그대로 노출합니다.
        # 운영 환경에서는 일반화된 오류 메시지를 반환하고 상세 오류는 서버 로그에만 기록해야 합니다.
        return templates.TemplateResponse(
            request,
            "error_debug.html",
            {
                "user": None,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "internal_hint": "app/routers/errors.py: general_error",
            },
        )


@router.get("/debug/db-error")
def database_error(request: Request, db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT * FROM not_existing_table"))
    except SQLAlchemyError as exc:
        db.rollback()
        # 실습을 위해 DB 오류 메시지를 가공하지 않고 화면에 노출합니다.
        # 운영 환경에서는 DB 상세 오류를 서버 로그에만 남겨야 합니다.
        return templates.TemplateResponse(
            request,
            "error_debug.html",
            {
                "user": None,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "internal_hint": "query: SELECT * FROM not_existing_table",
            },
        )


@router.get("/debug/path-error")
def path_error(request: Request):
    # 실습을 위해 내부 파일 경로를 사용자에게 그대로 노출합니다.
    # 운영 환경에서는 내부 경로와 모듈 정보를 응답에 포함하면 안 됩니다.
    return templates.TemplateResponse(
        request,
        "error_debug.html",
        {
            "user": None,
            "error_type": "InternalPathError",
            "error_message": "Internal path leak: /app/routers/errors.py",
            "internal_hint": "/Users/app/web/app/routers/errors.py",
        },
    )
