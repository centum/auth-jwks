import json
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from auth_jwks.jwt_validation import JWKS


def _generate_rsa_keypair():
    """Generate an RSA key pair for testing."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key


def _make_jwk(private_key, kid="test-kid", alg="RS256"):
    """Create a JWK dict from an RSA private key."""
    public_key = private_key.public_key()
    from jwt.algorithms import RSAAlgorithm

    jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = kid
    jwk_dict["alg"] = alg
    jwk_dict["use"] = "sig"
    return jwk_dict


def _make_signed_token(private_key, kid="test-kid", alg="RS256", payload=None):
    """Create a signed JWT for testing."""
    now = datetime.now(timezone.utc)
    default_payload = {
        "sub": "user-123",
        "iss": "https://issuer.example.com",
        "aud": "test-audience",
        "exp": now + timedelta(hours=1),
        "iat": now,
    }
    if payload:
        default_payload.update(payload)
    return pyjwt.encode(
        default_payload,
        private_key,
        algorithm=alg,
        headers={"kid": kid},
    )


@pytest.fixture
def rsa_key():
    return _generate_rsa_keypair()


@pytest.fixture
def jwk(rsa_key):
    return _make_jwk(rsa_key)


@pytest.fixture
def discovery_url():
    return "https://issuer.example.com/.well-known/openid-configuration"


class TestJWKS:
    def test_init(self, discovery_url):
        jwks = JWKS(discovery_url, aud="test-aud")
        assert jwks.discovery_url == discovery_url
        assert jwks._aud == "test-aud"

    def test_init_default_algorithms(self, discovery_url):
        jwks = JWKS(discovery_url)
        assert "RS256" in jwks._allowed_algorithms
        assert "ES256" in jwks._allowed_algorithms

    def test_normalize_url_fixes_scheme(self, discovery_url):
        jwks = JWKS(discovery_url)
        fixed = jwks._normalize_url("http://different.host/jwks")
        assert fixed.startswith("https://")
        assert "issuer.example.com" in fixed

    def test_normalize_url_disabled(self, discovery_url):
        jwks = JWKS(discovery_url, fix_local_url=False)
        url = "http://internal-host/jwks"
        assert jwks._normalize_url(url) == url

    async def test_refresh_fetches_keys(self, rsa_key, jwk, httpx_mock, discovery_url):
        httpx_mock.add_response(
            url=discovery_url,
            json={
                "issuer": "https://issuer.example.com",
                "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
            },
        )
        httpx_mock.add_response(
            url="https://issuer.example.com/.well-known/jwks.json",
            json={"keys": [jwk]},
        )

        jwks_client = JWKS(discovery_url, cache_ttl=300)
        keys = await jwks_client._refresh()
        assert "test-kid" in keys
        assert keys["test-kid"].alg == "RS256"
        assert keys["test-kid"].issuer == "https://issuer.example.com"
        await jwks_client.close()

    async def test_refresh_missing_issuer_raises(self, httpx_mock, discovery_url):
        httpx_mock.add_response(
            url=discovery_url,
            json={"jwks_uri": "https://issuer.example.com/jwks"},
        )
        jwks_client = JWKS(discovery_url)
        with pytest.raises(pyjwt.InvalidTokenError, match="missing issuer"):
            await jwks_client._refresh()
        await jwks_client.close()

    async def test_refresh_missing_jwks_uri_raises(self, httpx_mock, discovery_url):
        httpx_mock.add_response(
            url=discovery_url,
            json={"issuer": "https://issuer.example.com"},
        )
        jwks_client = JWKS(discovery_url)
        with pytest.raises(pyjwt.InvalidTokenError, match="missing jwks_uri"):
            await jwks_client._refresh()
        await jwks_client.close()

    async def test_refresh_skips_unsupported_algorithms(self, httpx_mock, discovery_url):
        httpx_mock.add_response(
            url=discovery_url,
            json={
                "issuer": "https://issuer.example.com",
                "jwks_uri": "https://issuer.example.com/jwks",
            },
        )
        httpx_mock.add_response(
            url="https://issuer.example.com/jwks",
            json={"keys": [{"kid": "k1", "alg": "PS256", "kty": "RSA"}]},
        )
        jwks_client = JWKS(discovery_url)
        keys = await jwks_client._refresh()
        assert len(keys) == 0
        await jwks_client.close()

    async def test_verify_token_success(self, rsa_key, jwk, httpx_mock, discovery_url):
        httpx_mock.add_response(
            url=discovery_url,
            json={
                "issuer": "https://issuer.example.com",
                "jwks_uri": "https://issuer.example.com/jwks",
            },
        )
        httpx_mock.add_response(
            url="https://issuer.example.com/jwks",
            json={"keys": [jwk]},
        )

        token = _make_signed_token(rsa_key)
        jwks_client = JWKS(discovery_url, aud="test-audience", leeway=60)
        payload = await jwks_client.verify_token(token)
        assert payload["sub"] == "user-123"
        await jwks_client.close()

    async def test_verify_token_with_bearer_prefix(self, rsa_key, jwk, httpx_mock, discovery_url):
        httpx_mock.add_response(
            url=discovery_url,
            json={
                "issuer": "https://issuer.example.com",
                "jwks_uri": "https://issuer.example.com/jwks",
            },
        )
        httpx_mock.add_response(
            url="https://issuer.example.com/jwks",
            json={"keys": [jwk]},
        )

        token = _make_signed_token(rsa_key)
        jwks_client = JWKS(discovery_url, aud="test-audience", leeway=60)
        payload = await jwks_client.verify_token(f"Bearer {token}")
        assert payload["sub"] == "user-123"
        await jwks_client.close()

    async def test_verify_token_no_audience(self, rsa_key, jwk, httpx_mock, discovery_url):
        httpx_mock.add_response(
            url=discovery_url,
            json={
                "issuer": "https://issuer.example.com",
                "jwks_uri": "https://issuer.example.com/jwks",
            },
        )
        httpx_mock.add_response(
            url="https://issuer.example.com/jwks",
            json={"keys": [jwk]},
        )

        token = _make_signed_token(rsa_key, payload={"aud": None})
        jwks_client = JWKS(discovery_url, aud=None, leeway=60)
        payload = await jwks_client.verify_token(token)
        assert payload["sub"] == "user-123"
        await jwks_client.close()

    async def test_close(self, discovery_url):
        jwks_client = JWKS(discovery_url)
        await jwks_client.close()
        assert jwks_client._client is None
        # closing twice should not raise
        await jwks_client.close()
