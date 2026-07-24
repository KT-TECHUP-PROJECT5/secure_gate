-- Upload table (initial upload rows are intentionally omitted)
CREATE TABLE IF NOT EXISTS uploads (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL UNIQUE,
    file_path VARCHAR(500) NOT NULL,
    content_type VARCHAR(255) NOT NULL,
    file_size INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL
);

-- Initial users
INSERT INTO users (username, password, nickname, role, created_at) VALUES ('admin', 'admin123', '관리자', 'admin', '2026-07-01T00:00:00');
INSERT INTO users (username, password, nickname, role, created_at) VALUES ('user1', 'password123', '사용자1', 'user', '2026-07-01T00:00:01');
INSERT INTO users (username, password, nickname, role, created_at) VALUES ('user2', 'password123', '사용자2', 'user', '2026-07-01T00:00:02');

-- Initial posts
INSERT INTO posts (user_id, title, content, is_private, created_at) VALUES (2, 'user1 공개 게시글', 'user1 공개 게시글 내용', FALSE, '2026-07-01T00:01:00');
INSERT INTO posts (user_id, title, content, is_private, created_at) VALUES (2, 'user1 비공개 게시글', 'user1 비공개 게시글 내용', TRUE, '2026-07-01T00:02:00');
INSERT INTO posts (user_id, title, content, is_private, created_at) VALUES (3, 'user2 공개 게시글', 'user2 공개 게시글 내용', FALSE, '2026-07-01T00:03:00');
INSERT INTO posts (user_id, title, content, is_private, created_at) VALUES (3, 'user2 비공개 게시글', 'user2 비공개 게시글 내용', TRUE, '2026-07-01T00:04:00');

-- Initial comments
INSERT INTO comments (post_id, user_id, content, created_at) VALUES (1, 2, 'user1 댓글', '2026-07-01T00:05:00');
INSERT INTO comments (post_id, user_id, content, created_at) VALUES (2, 3, 'user2 댓글', '2026-07-01T00:06:00');
