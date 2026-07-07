# Web ERD

```text
users
  ├── id (PK)
  ├── username
  ├── password
  ├── nickname
  ├── role
  └── created_at

posts
  ├── id (PK)
  ├── user_id (FK -> users.id)
  ├── title
  ├── content
  ├── is_private
  └── created_at

comments
  ├── id (PK)
  ├── post_id (FK -> posts.id)
  ├── user_id (FK -> users.id)
  ├── content
  └── created_at

uploads
  ├── id (PK)
  ├── user_id (FK -> users.id)
  ├── original_filename
  ├── stored_filename
  ├── file_path
  ├── content_type
  ├── file_size
  └── created_at
```

Relationships:
- users 1:N posts
- users 1:N comments
- posts 1:N comments
- users 1:N uploads
