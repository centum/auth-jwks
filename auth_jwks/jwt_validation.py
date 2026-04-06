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
        discovery_url: str | None = None,
        aud: str | None = None,
        allowed_algorithms: set[str] | None = None,
        cache_ttl: int = 900,
        leeway: float = 30.0,  # seconds of time
        timeout: float = 5.0,
        retries: int = 3,
        fix_local_url: bool = True,
        *,
        jwks_uri: str | None = None,
        issuer: str | None = None,
    ) -> None:
        if discovery_url is None and jwks_uri is None:
            msg = "Either 'discovery_url' or 'jwks_uri' must be provided"
            raise ValueError(msg)

        if discovery_url is not None and issuer is not None and jwks_uri is None:
            msg = (
                "'issuer' cannot be used with 'discovery_url' alone"
                " (issuer is obtained from discovery);"
                " use 'jwks_uri' for explicit issuer control"
            )
            raise ValueError(msg)

        if jwks_uri is not None and issuer is None:
            logger.warning(
                "No issuer configured for direct jwks_uri mode; "
                "issuer claim validation will be skipped"
            )

        super().__init__(
            aud=aud,
            leeway=leeway,
            cache_ttl=cache_ttl,
        )
        self._discovery_url = discovery_url
        self._jwks_uri = jwks_uri
        self._issuer = issuer

        base_url = jwks_uri if jwks_uri is not None else discovery_url
        if base_url is None:  # pragma: no cover – unreachable after validation
            msg = "base_url resolved to None unexpectedly"
            raise RuntimeError(msg)
        parts = urlparse(base_url)
        self._scheme = parts.scheme
        self._netloc = parts.netloc

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

        if self._jwks_uri is not None:
            # Direct mode: fetch keys from jwks_uri without discovery
            r = await self._client.get(self._jwks_uri)
            r.raise_for_status()
            jwks = r.json()
            return self._parse_jwk_keys(
                jwks.get("keys", []), self._issuer, self._allowed_algorithms
            )

        # discovery mode: fetch OpenID configuration and then JWKS
        assert self._discovery_url is not None  # guaranteed by __init__ validation
        r = await self._client.get(self._discovery_url)
        r.raise_for_status()
        conf = r.json()

        logger.debug("OpenID Configuration discovery from %s -> %s", self._discovery_url, conf)

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
        audience: str | Iterable[str] | None = None,
        *,
        verify_iss: bool = True,
    ) -> dict[str, Any]:
        """
        Validate token sign by JWKS and validate standard claims.
        Works with both ID Tokens and Access Tokens in JWT format.

        Parameters:
            token: JWT token (can include 'Bearer ' prefix which will be removed)
            audience: expected audience value(s)
            verify_iss: whether to verify the issuer claim

        Returns:
            Decoded JWT payload if validation is successful

        Raises:
            InvalidTokenError if validation fails
        """

        # In direct mode without an explicit issuer, issuer validation is impossible;
        # force verify_iss=False regardless of what the caller passed to avoid
        # silently accepting any issuer when key_obj.issuer is None.
        effective_verify_iss = verify_iss and (self._jwks_uri is None or self._issuer is not None)

        verify_aud = bool(audience or self._aud)

        options: Options = {
            "verify_signature": True,
            "verify_exp": True,
            "verify_iss": effective_verify_iss,
            "verify_aud": verify_aud,
            "require": ["exp", "iat", "sub"]
            + (["iss"] if effective_verify_iss else [])
            + (["aud"] if verify_aud else []),
        }
        return await self._verify_token(
            token,
            audience=audience,
            options=options,
        )
