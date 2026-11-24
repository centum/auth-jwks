import asyncio
import logging

import jwt as pyjwt
import pytest

from auth_jwks.base import BaseJWKClient, KeyObject


class ConcreteJWKClient(BaseJWKClient):
    """Concrete implementation for testing the abstract base."""

    def __init__(self, keys: dict[str, KeyObject] | None = None, **kwargs):
        super().__init__(**kwargs)
        self._test_keys = keys or {}
        self.refresh_count = 0

    async def _refresh(self) -> dict[str, KeyObject]:
        self.refresh_count += 1
        return dict(self._test_keys)


class TestKeyObject:
    def test_named_tuple(self):
        key_obj = KeyObject(key="pub_key", alg="RS256", issuer="https://issuer.com")
        assert key_obj.key == "pub_key"
        assert key_obj.alg == "RS256"
        assert key_obj.issuer == "https://issuer.com"


class TestBaseJWKClientCleanToken:
    def test_strips_whitespace(self):
        assert BaseJWKClient._clean_token("  token  ") == "token"

    def test_removes_bearer_prefix(self):
        assert BaseJWKClient._clean_token("Bearer my_token") == "my_token"

    def test_removes_bearer_case_insensitive(self):
        assert BaseJWKClient._clean_token("bearer my_token") == "my_token"

    def test_no_prefix(self):
        assert BaseJWKClient._clean_token("plain_token") == "plain_token"


class TestBaseJWKClientGetKid:
    def test_invalid_token_raises(self):
        with pytest.raises(pyjwt.InvalidTokenError, match="Invalid token header"):
            BaseJWKClient._get_kid("not.a.valid.token")

    def test_token_without_kid_raises(self):
        # Create a token without kid in header
        token = pyjwt.encode({"sub": "1"}, "secret", algorithm="HS256")
        with pytest.raises(pyjwt.InvalidTokenError, match="Invalid token header"):
            BaseJWKClient._get_kid(token)


class TestBaseJWKClientGetKey:
    async def test_get_key_triggers_refresh(self):
        key_obj = KeyObject(key="pub", alg="RS256", issuer="iss")
        client = ConcreteJWKClient(keys={"kid1": key_obj})
        result = await client.get_key("kid1")
        assert result == key_obj
        assert client.refresh_count == 1

    async def test_get_key_cache_hit(self):
        key_obj = KeyObject(key="pub", alg="RS256", issuer="iss")
        client = ConcreteJWKClient(keys={"kid1": key_obj}, cache_ttl=300)
        await client.get_key("kid1")
        await client.get_key("kid1")
        assert client.refresh_count == 1  # only refreshed once

    async def test_get_key_unknown_kid_raises(self):
        client = ConcreteJWKClient(keys={})
        with pytest.raises(pyjwt.InvalidKeyError, match="Unknown kid"):
            await client.get_key("nonexistent")

    async def test_get_key_cache_expired(self):
        key_obj = KeyObject(key="pub", alg="RS256", issuer="iss")
        client = ConcreteJWKClient(keys={"kid1": key_obj}, cache_ttl=0)
        await client.get_key("kid1")
        # cache_ttl=0 means always expired
        await client.get_key("kid1")
        assert client.refresh_count == 2

    async def test_get_key_refreshes_when_kid_missing(self):
        """If kid not in cache but cache not expired, should still refresh."""
        key_obj1 = KeyObject(key="pub1", alg="RS256", issuer="iss")
        client = ConcreteJWKClient(keys={"kid1": key_obj1}, cache_ttl=300)

        await client.get_key("kid1")
        assert client.refresh_count == 1

        # Now add kid2 to the keys that _refresh returns
        key_obj2 = KeyObject(key="pub2", alg="RS256", issuer="iss")
        client._test_keys["kid2"] = key_obj2

        client._refreshed_at -= client.unknown_kid_refresh_interval
        result = await client.get_key("kid2")
        assert result == key_obj2
        assert client.refresh_count == 2

    async def test_unknown_kid_refresh_is_throttled(self):
        key_obj = KeyObject(key="pub", alg="RS256", issuer="iss")
        client = ConcreteJWKClient(keys={"kid1": key_obj}, cache_ttl=300)
        await client.get_key("kid1")

        for _ in range(5):
            with pytest.raises(pyjwt.InvalidKeyError, match="Unknown kid"):
                await client.get_key("random")
        assert client.refresh_count == 1

        client._refreshed_at -= client.unknown_kid_refresh_interval
        with pytest.raises(pyjwt.InvalidKeyError, match="Unknown kid"):
            await client.get_key("random")
        assert client.refresh_count == 2

    async def test_concurrent_unknown_kids_refresh_once(self):
        key_obj = KeyObject(key="pub", alg="RS256", issuer="iss")
        client = ConcreteJWKClient(keys={"kid1": key_obj}, cache_ttl=300)
        await client.get_key("kid1")
        client._refreshed_at -= client.unknown_kid_refresh_interval

        results = await asyncio.gather(
            *(client.get_key(f"random{i}") for i in range(10)), return_exceptions=True
        )
        assert all(isinstance(r, pyjwt.InvalidKeyError) for r in results)
        assert client.refresh_count == 2

    async def test_known_kid_unaffected_by_throttle(self):
        key_obj = KeyObject(key="pub", alg="RS256", issuer="iss")
        client = ConcreteJWKClient(keys={"kid1": key_obj}, cache_ttl=300)
        await client.get_key("kid1")
        with pytest.raises(pyjwt.InvalidKeyError):
            await client.get_key("random")
        assert await client.get_key("kid1") == key_obj
        assert client.refresh_count == 1


class TestVerifyTokenLogging:
    async def test_invalid_header_logged_as_warning(self, caplog):
        client = ConcreteJWKClient()
        with pytest.raises(pyjwt.InvalidTokenError):
            await client._verify_token("not-a-jwt")
        assert caplog.records
        assert all(r.levelno == logging.WARNING for r in caplog.records)

    async def test_unknown_kid_logged_as_warning(self, caplog):
        client = ConcreteJWKClient()
        token = pyjwt.encode({"sub": "x"}, "secret", algorithm="HS256", headers={"kid": "nope"})
        with pytest.raises(pyjwt.InvalidTokenError):
            await client._verify_token(token)
        assert caplog.records
        assert all(r.levelno == logging.WARNING for r in caplog.records)
