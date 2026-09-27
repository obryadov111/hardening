from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from jose import jwt
from sqlalchemy.orm import Session

from app.api.deps import get_current_user_allow_password_change, get_db
from app.api.routes.twofa import check_second_factor
from app.core.config import settings
from app.core.security import (
    create_access_token,
    hash_password,
    password_problem,
    verify_password,
)
from app.models.user import User
from app.models.user_2fa import User2FA
from app.schemas.auth import ChangePasswordRequest, LoginRequest, LoginResponse, MeResponse, Verify2FARequest
from app.services.login_guard import check_password, ensure_not_locked, register_failure, register_success

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.lower().strip()).first()
    # Блокировка — до проверки пароля: во время неё подбор ничего не даёт (services/login_guard.py).
    ensure_not_locked(user)
    if not check_password(user, payload.password):
        register_failure(db, user)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный логин или пароль")

    if not user.is_active or user.account_status != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Пользователь не активен")

    twofa = db.query(User2FA).filter(User2FA.user_id == user.id).first()
    if twofa and twofa.is_enabled:
        # Счётчик неудач не сбрасывается до верного кода: иначе, зная пароль, можно было бы
        # бесконечно подбирать код, чередуя попытки с верным паролем. Токен — короткоживущий.
        temp_token = jwt.encode(
            {
                "sub": str(user.id),
                "type": "pre_2fa",
                "exp": datetime.now(UTC) + timedelta(minutes=settings.PRE_2FA_TOKEN_EXPIRE_MINUTES),
            },
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )
        return LoginResponse(two_factor_required=True, temp_token=temp_token)

    register_success(user)
    user.last_login_at = datetime.now(UTC)
    db.commit()
    return LoginResponse(access_token=create_access_token(str(user.id)))


@router.post("/verify-2fa", response_model=LoginResponse)
def verify_2fa(payload: Verify2FARequest, db: Session = Depends(get_db)):
    try:
        token_payload = jwt.decode(payload.temp_token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недействительный временный токен") from exc

    if token_payload.get("type") != "pre_2fa" or "exp" not in token_payload:
        # без exp — токен выдан до ограничения срока; такие не принимаются
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный тип токена")

    user_id = token_payload.get("sub")
    user = db.query(User).filter(User.id == user_id).first()
    twofa = db.query(User2FA).filter(User2FA.user_id == user_id).first()

    if not user or not twofa or not twofa.is_enabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="2FA не настроен")

    ensure_not_locked(user)
    if not user.is_active or user.account_status != "active":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Пользователь не активен")

    # код из приложения или одноразовый резервный код (если телефона нет под рукой)
    if not check_second_factor(db, twofa, payload.code):
        register_failure(db, user)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверный код 2FA")

    register_success(user)
    user.last_login_at = datetime.now(UTC)
    db.commit()  # twofa.last_used_at уже записан при приёме кода (защита от повтора)

    return LoginResponse(access_token=create_access_token(str(user.id)))


@router.get("/me", response_model=MeResponse)
def me(current_user: User = Depends(get_current_user_allow_password_change)):
    return MeResponse(
        id=str(current_user.id),
        email=current_user.email,
        display_name=current_user.display_name,
        is_superadmin=current_user.is_superadmin,
        account_status=current_user.account_status,
        must_change_password=current_user.must_change_password,
    )


@router.post("/change-password", response_model=LoginResponse)
def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user_allow_password_change),
    db: Session = Depends(get_db),
):
    """Смена своего пароля (в т.ч. временного, выданного администратором). Все прежние сессии
    отзываются; в ответе — новый токен для текущей."""
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Текущий пароль неверен")
    problem = password_problem(payload.new_password, current_user.email)
    if problem:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Новый пароль не подходит: {problem}")
    if verify_password(payload.new_password, current_user.password_hash):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Новый пароль должен отличаться от текущего")

    now = datetime.now(UTC)
    current_user.password_hash = hash_password(payload.new_password)
    current_user.must_change_password = False
    current_user.password_changed_at = now
    current_user.updated_at = now
    db.commit()
    return LoginResponse(access_token=create_access_token(str(current_user.id)))