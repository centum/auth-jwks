import asyncio
import logging
import time
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any, NamedTuple

import httpx
import jwt  # PyJWT
from jwt.algorithms import ECAlgorithm, RSAAlgorithm
from jwt.types import Options

logger = logging.getLogger(__name__)


class KeyObject(NamedTuple):
    key: Any
    alg: str
    issuer: str


class BaseJWKClient(ABC):
    def __init__(
        self,
        *,
        cache_ttl: float | int = 900.0,
        leeway: float = 30.0,
    ) -> None:
        self._leeway = leeway
        self._cache_ttl = cache_ttl

        self._lock = asyncio.Lock()
        self._keys_by_kid: dict[str, KeyObject] = {}
        self._expires_at = 0.0
        self._client: httpx.AsyncClient | None = None

    @classmethod
    def _get_kid(cls, token: str) -> str:
        try:
            header = jwt.get_unverified_header(token)
            return header["kid"]
        except (jwt.PyJWTError, AttributeError, KeyError) as e:
            logger.error("Invalid token header: %s", e)
            raise jwt.InvalidTokenError("Invalid token header") from e

    @classmethod
    def _clean_token(cls, token: str) -> str:
        token = token.strip()
        parts = token.split(" ", 1)
        if len(parts) > 1 and parts[0].lower() == "bearer":
            token = parts[1]
        return token

    @staticmethod
    def _parse_jwk_keys(
        jwks_keys: list[dict[str, Any]], issuer: str, allowed_algorithms: set[str]
    ) -> dict[str, KeyObject]:
        keys: dict[str, KeyObject] = {}
        for jwk in jwks_keys:
            kid = jwk.get("kid")
            alg = jwk.get("alg")
            if not kid or not alg or alg not in allowed_algorithms:
                continue
            if alg == "RS256":
                keys[kid] = KeyObject(
                    key=RSAAlgorithm.from_jwk(jwk),
                    alg=alg,
                    issuer=issuer,
                )
            elif alg == "ES256":
                keys[kid] = KeyObject(
                    key=ECAlgorithm.from_jwk(jwk),
                    alg=alg,
                    issuer=issuer,
                )
        return keys

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_key(self, kid: str) -> KeyObject:
        now = time.monotonic()
        if now < self._expires_at and kid in self._keys_by_kid:
            return self._keys_by_kid[kid]

        async with self._lock:
            # double-check under lock
            now = time.monotonic()
            if now >= self._expires_at or kid not in self._keys_by_kid:
                self._keys_by_kid = await self._refresh()
                self._expires_at = time.monotonic() + self._cache_ttl

        key_object = self._keys_by_kid.get(kid)
        if key_object is None:
            raise jwt.InvalidKeyError("Unknown kid")
        return key_object

    @abstractmethod
    async def _refresh(self) -> dict[str, KeyObject]: ...

    async def _verify_token(
        self,
        token: str,
        *,
        audience: str | Iterable[str] | None = None,
        options: Options | None = None,
    ) -> dict[str, Any]:
        token = self._clean_token(token)

        resolved_options: Options = options or {}

        # Hints:
        # - algorithms: by default Hydra use RS256 for ID Token
        # - audience: must included client_id
        # - issuer: must equal to discovery issuer
        # - leeway: a small slack for the clock
        try:
            kid = self._get_kid(token)
            key_obj = await self.get_key(kid)

            payload = jwt.decode(
                token,
                key_obj.key,
                algorithms=[key_obj.alg],
                issuer=key_obj.issuer,
                audience=audience,
                options=resolved_options,
                leeway=self._leeway,
            )
            return payload

        except jwt.InvalidKeyError as e:
            logger.error("Invalid key: %s", e)
            raise jwt.InvalidTokenError("Failed to verify token") from e

        except jwt.InvalidTokenError:
            raise

        except httpx.HTTPError as e:
            logger.exception("HTTP error while fetching discovery/JWKS: %s", e)
            raise jwt.InvalidTokenError("Failed to fetch JWKS") from e

        except Exception as e:
            logger.exception("Unexpected error while verifying token: %s", e)
            raise jwt.InvalidTokenError("Failed to verify token") from e
