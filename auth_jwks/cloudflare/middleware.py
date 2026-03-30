import logging
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from auth_jwks.cloudflare.client import User

logger = logging.getLogger(__name__)

VerifyToken = Callable[[str], Awaitable[User]]


class CfaAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        verify_token: VerifyToken | None = None,
        dev_user: User | None = None,
        header_name: str = "Cf-Access-Jwt-Assertion",
        cookie_name: str = "CF_Authorization",
    ) -> None:
        super().__init__(app)
        self._dev_user = dev_user
        self._verify_token = verify_token
        self._header_name = header_name
        self._cookie_name = cookie_name

    async def dispatch(
        self, request: Request, call_next: Callable[..., Awaitable[Response]]
    ) -> Response:
        if self._dev_user:
            request.state.user = self._dev_user
            return await call_next(request)

        acc_key = request.headers.get(self._header_name) or request.cookies.get(self._cookie_name)
        if not acc_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid CFA Token"},
            )
        try:
            request.state.user = await self._verify_token(acc_key)  # type: ignore[misc]
        except Exception:
            logger.exception("CFA token verification failed")
            return JSONResponse(
                status_code=401,
                content={"detail": "CFA token verification failed"},
            )
        return await call_next(request)
