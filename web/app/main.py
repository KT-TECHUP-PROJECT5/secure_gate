from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import get_settings
from app.routers.admin import router as admin_router
from app.routers.auth import router as auth_router
from app.routers.comments import router as comments_router
from app.routers.errors import router as errors_router
from app.routers.posts import router as posts_router
from app.routers.upload import router as upload_router

BASE_DIR = Path(__file__).resolve().parent.parent

settings = get_settings()
app = FastAPI(title=settings.app_name, version="1.0.0", debug=settings.debug)
# 실습을 위해 세션 만료 시간을 명확히 제한하지 않았습니다.
# 운영 환경에서는 적절한 idle timeout과 absolute timeout이 필요합니다.
app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, same_site="lax")
app.mount("/static", StaticFiles(directory=BASE_DIR / "app" / "static"), name="static")

app.include_router(auth_router)
app.include_router(posts_router)
app.include_router(comments_router)
app.include_router(admin_router)
app.include_router(errors_router)
app.include_router(upload_router)
