from sqlalchemy import select

from app.core.database import SessionLocal
from app.models.post import Post
from app.models.user import User


def seed_database() -> None:
    with SessionLocal() as db:
        if db.scalar(select(User.id).limit(1)) is not None:
            print("seed skipped: users table is not empty")
            return

        admin = User(username="admin", password="admin123", nickname="관리자", role="admin")
        user1 = User(username="user1", password="password123", nickname="사용자1")
        user2 = User(username="user2", password="password123", nickname="사용자2")
        db.add_all([admin, user1, user2])
        db.flush()

        db.add_all(
            [
                Post(user_id=user1.id, title="user1 공개 게시글", content="공개 글입니다."),
                Post(
                    user_id=user1.id,
                    title="user1 비공개 게시글",
                    content="IDOR 확인용 비공개 글입니다.",
                    is_private=True,
                ),
                Post(user_id=user2.id, title="user2 공개 게시글", content="공개 글입니다."),
                Post(
                    user_id=user2.id,
                    title="user2 비공개 게시글",
                    content="다른 계정에서 직접 접근해 보세요.",
                    is_private=True,
                ),
            ]
        )
        db.commit()
        print("seed complete")


if __name__ == "__main__":
    seed_database()
