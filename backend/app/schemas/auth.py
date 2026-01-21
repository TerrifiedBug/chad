from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SetupRequest(BaseModel):
    admin_email: EmailStr
    admin_password: str
    opensearch_host: str
    opensearch_port: int = 9200
    opensearch_username: str | None = None
    opensearch_password: str | None = None
    opensearch_use_ssl: bool = True
