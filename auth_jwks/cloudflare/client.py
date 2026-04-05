import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx
from jwt.types import Options

from ..base import BaseJWKClient, KeyObject

logger = logging.getLogger(__name__)

_TEAM_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]*$")


@dataclass(frozen=True, slots=True)
class User:
    sub: str
    email: str
    country: str | None = None
    exists_identity: bool = False


@dataclass(frozen=True, slots=True)
class Identity:
    email: str | None = None
    user_uuid: str | None = None
    account_id: str | None = None
    iat: int | None = None
    ip: str | None = None
    auth_status: str | None = None
    common_name: str | None = None
    service_token_id: str | None = None
    service_token_status: str | None = None
    is_warp: bool | None = None
    is_gateway: bool | None = None
    gateway_account_id: str | None = None
    device_id: str | None = None
    version: str | None = None
    device_sessions: list[str] | None = None
    idp: dict[str, Any] | None = None
    geo: dict[str, Any] | None = None
    device_posture: dict[str, Any] | None = None


class CloudFlareTokenValidation(BaseJWKClient):
    def __init__(
        self,
        *,
        aud: str,
        team: str,
        allowed_algorithms: set[str] | None = None,
        cache_ttl: int = 900,
        leeway: float = 30.0,  # seconds of time
        retries: int = 3,
        timeout: float = 5.0,
    ):
        if not _TEAM_PATTERN.match(team):
            raise ValueError(
                f"Invalid team name: {team!r}. Must start with an"
                " alphanumeric character and contain only"
                " alphanumeric characters and hyphens."
            )
        super().__init__(
            leeway=leeway,
            cache_ttl=cache_ttl,
        )
        self.aud = aud

        self.issuer = f"https://{team}.cloudflareaccess.com"
        self.cert_url = f"https://{team}.cloudflareaccess.com/cdn-cgi/access/certs"
        self.identity_url = f"https://{team}.cloudflareaccess.com/cdn-cgi/access/get-identity"

        self._allowed_algorithms = allowed_algorithms or {"RS256", "ES256"}

        self._client = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(retries=retries),
            timeout=httpx.Timeout(timeout),
        )

    async def _refresh(self) -> dict[str, KeyObject]:
        if self._client is None:
            raise RuntimeError("Client is closed")

        response = await self._client.get(self.cert_url)
        response.raise_for_status()
        jwks = response.json()

        return self._parse_jwk_keys(jwks.get("keys", []), self.issuer, self._allowed_algorithms)

    async def verify_token(
        self,
        token: str,
    ) -> dict[str, Any]:
        """
        Validate token sign by JWKS and validate standard claims.
        Works with both ID Tokens and Access Tokens in JWT format.

        Parameters:
            token: JWT token (can include 'Bearer ' prefix which will be removed)

        Returns:
            Decoded JWT payload if validation is successful

        Raises:
            InvalidTokenError if validation fails
        """
        options: Options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": True,
            "require": ["exp", "iat", "iss", "aud", "email", "sub"],
        }

        return await self._verify_token(
            token,
            audience=self.aud,
            options=options,
        )

    async def verify_email(
        self,
        token: str,
    ) -> str:
        payload = await self.verify_token(token)
        return payload["email"]

    async def verify_user(self, token: str) -> User:
        payload = await self.verify_token(token)
        return User(
            sub=payload["sub"],
            email=payload["email"],
            country=payload.get("country"),
            exists_identity=bool(payload.get("identity_nonce")),
        )

    async def get_identity(self, token: str) -> Identity:
        if self._client is None:
            raise RuntimeError("Client is closed")

        response = await self._client.get(self.identity_url, cookies={"CF_Authorization": token})
        response.raise_for_status()
        payload = response.json()
        return Identity(
            email=payload.get("email"),
            user_uuid=payload.get("user_uuid"),
            account_id=payload.get("account_id"),
            iat=payload.get("iat"),
            ip=payload.get("ip"),
            auth_status=payload.get("auth_status"),
            common_name=payload.get("cn"),
            service_token_id=payload.get("service_token_id"),
            service_token_status=payload.get("service_token_status"),
            is_warp=payload.get("is_warp"),
            is_gateway=payload.get("is_gateway"),
            gateway_account_id=payload.get("gateway_account_id"),
            device_id=payload.get("device_id"),
            version=payload.get("version"),
            device_sessions=payload.get("device_sessions"),
            idp=payload.get("idp"),
            geo=payload.get("geo"),
            device_posture=payload.get("devicePosture"),
        )
