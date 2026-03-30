import logging
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import jwt  # PyJWT
from jwt.types import Options

from .base import BaseJWKClient, KeyObject

logger = logging.getLogger(__name__)


class JWKS(BaseJWKClient):
    def __init__(
        self,
        discovery_url: str,
        aud: str | None = None,
        allowed_algorithms: set[str] | None = None,
        cache_ttl: int = 900,
        leeway: float = 30.0,  # seconds of time
        timeout: float = 5.0,
        retries: int = 3,
        fix_local_url: bool = True,
    ) -> None:
        super().__init__(
            leeway=leeway,
            cache_ttl=cache_ttl,
        )
        self.discovery_url = discovery_url

        parts = urlparse(self.discovery_url)
        self._scheme = parts.scheme
        self._netloc = parts.netloc

        self._aud = aud
        self._allowed_algorithms = allowed_algorithms or {"RS256", "ES256"}

        self._client = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(retries=retries),
            timeout=httpx.Timeout(timeout),
        )

        self._fix_local_url = fix_local_url

    def _normalize_url(self, url: str) -> str:
        """Fix jwks_uri for short access to hydra"""
        if not self._fix_local_url:
            return url
        return str(urlunparse(urlparse(url)._replace(scheme=self._scheme, netloc=self._netloc)))

    async def _refresh(self) -> dict[str, KeyObject]:
        if self._client is None:
            raise RuntimeError("Client is closed")

        r = await self._client.get(self.discovery_url)
        r.raise_for_status()
        conf = r.json()

        logger.debug("OpenID Configuration discovery from %s -> %s", self.discovery_url, conf)

        issuer = conf.get("issuer")
        if not issuer:
            raise jwt.InvalidTokenError("OpenID discovery response missing issuer")

        jwks_uri = conf.get("jwks_uri")
        if not jwks_uri:
            raise jwt.InvalidTokenError("OpenID discovery response missing jwks_uri")
        jwks_uri = self._normalize_url(jwks_uri)

        r = await self._client.get(jwks_uri)
        r.raise_for_status()
        jwks = r.json()

        return self._parse_jwk_keys(jwks.get("keys", []), issuer, self._allowed_algorithms)

    async def verify_token(
        self,
        token: str,
        expected_audience: str | Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """
        Validate token sign by JWKS and validate standard claims.
        Works with both ID Tokens and Access Tokens in JWT format.

        Parameters:
            token: JWT token (can include 'Bearer ' prefix which will be removed)
            expected_audience: expected audience value(s)

        Returns:
            Decoded JWT payload if validation is successful

        Raises:
            InvalidTokenError if validation fails
        """
        if expected_audience is None:
            expected_audience = self._aud
        verify_aud = bool(expected_audience)

        options: Options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": True,
            "verify_aud": verify_aud,
            "require": ["exp", "iat", "iss", "sub"] + (["aud"] if verify_aud else []),
        }
        return await self._verify_token(
            token,
            audience=expected_audience,
            options=options,
        )
