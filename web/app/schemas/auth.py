from pydantic import BaseModel, Field


class RegisterForm(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=4, max_length=255)
    nickname: str = Field(min_length=1, max_length=50)
