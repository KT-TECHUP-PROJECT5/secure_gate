from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    password: Mapped[str] = mapped_column(String(255))
    nickname: Mapped[str] = mapped_column(String(50))
    role: Mapped[str] = mapped_column(String(20), default="user")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    posts: Mapped[list["Post"]] = relationship(back_populates="user")  # noqa: F821
    comments: Mapped[list["Comment"]] = relationship(back_populates="user")  # noqa: F821
    uploads: Mapped[list["UploadFileRecord"]] = relationship(  # noqa: F821
        back_populates="user"
    )
