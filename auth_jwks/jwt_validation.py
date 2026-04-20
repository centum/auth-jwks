import logging
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import jwt  # PyJWT
from jwt.types import Options

from .base import BaseJWKClient, KeyObject

logger = logging.getLogger(__name__)


class IssuerMismatchError(jwt.InvalidTokenError):
    """Raised when configured issuer disagrees with OIDC discovery document."""


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
        """Initialise the JWKS client.

        At least one of ``discovery_url`` or ``jwks_uri`` must be provided.
        When both are given, ``jwks_uri`` takes precedence and discovery is skipped.

        Parameters:
            discovery_url: OpenID Connect discovery endpoint
                (``.well-known/openid-configuration``).
            aud: Expected audience claim value. Validation is skipped when ``None``.
            allowed_algorithms: Set of accepted signing algorithms.
                Defaults to ``{"RS256", "ES256"}``.
            cache_ttl: Key cache lifetime in seconds (default 900 = 15 min).
            leeway: Clock skew tolerance in seconds for ``exp``/``nbf`` checks.
            timeout: HTTP request timeout in seconds.
            retries: Number of HTTP retries on transient failures.
            fix_local_url: When ``True``, normalize the scheme and host of
                ``jwks_uri`` discovered from the OIDC document to match the
                ``discovery_url`` (useful for local/Docker environments).
            jwks_uri: Direct JWKS endpoint URL. When provided, discovery is
                skipped and keys are fetched from this URL directly.
            issuer: Expected issuer claim value (non-empty string or ``None``).
                In discovery mode: cross-checked against the OIDC document's ``issuer``
                field on every cache refresh; raises :exc:`IssuerMismatchError` on
                disagreement. When omitted, the discovery document is trusted
                unconditionally and a ``WARNING`` is emitted.
                In direct mode: passed to PyJWT for ``iss`` validation; omitting it
                skips issuer validation entirely.
                Passing ``issuer=""`` raises :exc:`ValueError`.

        Raises:
            ValueError: If neither ``discovery_url`` nor ``jwks_uri`` is provided,
                or if ``issuer`` is an empty string.
            IssuerMismatchError: Raised during ``_refresh()`` (not at construction
                time) when the configured ``issuer`` disagrees with the OIDC
                discovery document's ``issuer`` field.
                :exc:`IssuerMismatchError` is a subclass of
                ``jwt.InvalidTokenError``, so existing
                ``except jwt.InvalidTokenError:`` blocks continue to work without
                modification.
        """
        if discovery_url is None and jwks_uri is None:
            msg = "Either 'discovery_url' or 'jwks_uri' must be provided"
            raise ValueError(msg)

        if issuer is not None and not issuer.strip():
            msg = "'issuer' must be a non-empty string or None"
            raise ValueError(msg)

        if discovery_url is not None and jwks_uri is None and issuer is None:
            logger.warning(
                "Discovery mode without explicit issuer: library will trust the issuer from OIDC"
                " document. For defence-in-depth, pass 'issuer=...' so its value is cross-checked"
                " against discovery."
            )

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
        """Normalize scheme and host of a JWKS URI to match the discovery URL.

        Useful for local/Docker environments where the JWKS URI hostname differs.
        """
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

        discovery_issuer = conf.get("issuer")
        if not discovery_issuer:
            raise jwt.InvalidTokenError("OpenID discovery response missing issuer")

        if self._issuer is not None and discovery_issuer != self._issuer:
            msg = (
                f"Issuer mismatch: configured '{self._issuer}' "
                f"differs from discovery document '{discovery_issuer}'"
            )
            raise IssuerMismatchError(msg)

        effective_issuer = self._issuer if self._issuer is not None else discovery_issuer

        jwks_uri = conf.get("jwks_uri")
        if not jwks_uri:
            raise jwt.InvalidTokenError("OpenID discovery response missing jwks_uri")
        jwks_uri = self._normalize_url(jwks_uri)

        r = await self._client.get(jwks_uri)
        r.raise_for_status()
        jwks = r.json()

        return self._parse_jwk_keys(
            jwks.get("keys", []), effective_issuer, self._allowed_algorithms
        )

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
