from pydantic import BaseModel, EmailStr


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str | None = None
    token_type: str = "bearer"
    two_factor_required: bool = False
    temp_token: str | None = None


class Verify2FARequest(BaseModel):
    temp_token: str
    code: str


class MeResponse(BaseModel):
    id: str
    email: str
    display_name: str | None = None
    is_superadmin: bool
    account_status: str
    must_change_password: bool = False


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str