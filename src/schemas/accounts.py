from pydantic import BaseModel, EmailStr, validator, field_validator
from database.validators.accounts import validate_email, validate_password_strength

class UserRegistrationRequestSchema(BaseModel):
    email: str
    password: str

    @validator('password')
    def password_strength(cls, v):
        return validate_password_strength(v)

    @validator('email')
    def email_valid(cls, v):
        return validate_email(v)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(PasswordResetRequestSchema):
    token: str
    password: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
