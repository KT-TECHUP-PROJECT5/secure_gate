import shutil
from pathlib import Path
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common.auth import get_current_user
from app.core.database import get_db
from app.models.upload import UploadFileRecord
from app.models.user import User

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
templates = Jinja2Templates(directory=BASE_DIR / "templates")

router = APIRouter()


@router.get("/upload")
def upload_page(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)

    uploads = db.execute(
        select(
            UploadFileRecord.id,
            UploadFileRecord.original_filename,
            UploadFileRecord.file_size,
            UploadFileRecord.created_at,
            User.nickname.label("uploader"),
        )
        .join(User, UploadFileRecord.user_id == User.id)
        .order_by(UploadFileRecord.id.desc())
    ).all()
    return templates.TemplateResponse(
        request,
        "upload.html",
        {"user": user, "uploads": uploads},
    )


@router.post("/upload")
def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    user = get_current_user(request, db)
    if user is None:
        return RedirectResponse(url="/login", status_code=303)

    original_filename = file.filename or "unnamed"
    suffix = Path(original_filename).suffix
    stored_filename = f"{uuid4().hex}{suffix}"
    destination = UPLOAD_DIR / stored_filename

    # 실습을 위해 파일 확장자, MIME Type, 파일 크기 검증을 의도적으로 누락했습니다.
    # 운영 환경에서는 확장자 allowlist, MIME Type 검증, 파일 크기 제한,
    # 저장 경로 분리, 악성 파일 검사가 필요합니다.
    # 별도 보안 이벤트 로그도 남기지 않아 위험 확장자 업로드가 탐지되지 않습니다.
    with destination.open("wb") as output:
        shutil.copyfileobj(file.file, output)

    record = UploadFileRecord(
        user_id=user.id,
        original_filename=original_filename,
        stored_filename=stored_filename,
        file_path=str(destination),
        content_type=file.content_type or "application/octet-stream",
        file_size=destination.stat().st_size,
    )
    db.add(record)
    db.commit()
    return RedirectResponse(url="/upload", status_code=303)


@router.get("/download/{upload_id}")
def download_file(upload_id: int, db: Session = Depends(get_db)):
    record = db.get(UploadFileRecord, upload_id)
    if record is None or not Path(record.file_path).is_file():
        return RedirectResponse(url="/upload", status_code=303)

    return FileResponse(
        path=record.file_path,
        filename=record.original_filename,
        media_type="application/octet-stream",
    )
