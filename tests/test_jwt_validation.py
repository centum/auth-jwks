import json
from datetime import datetime, timedelta, timezone

import httpx
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
    if payload is not None:
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
        assert jwks._discovery_url == discovery_url
        assert jwks._aud == "test-aud"

    def test_init_default_algorithms(self, discovery_url):
        jwks = JWKS(discovery_url)
        assert "RS256" in jwks._allowed_algorithms
        assert "ES256" in jwks._allowed_algorithms

    def test_init_jwks_uri_only(self):
        jwks = JWKS(jwks_uri="https://example.com/jwks")
        assert jwks._jwks_uri == "https://example.com/jwks"
        assert jwks._discovery_url is None

    def test_init_discovery_url_only(self, discovery_url):
        jwks = JWKS(discovery_url)
        assert jwks._discovery_url == discovery_url
        assert jwks._jwks_uri is None

    def test_init_both_provided(self, discovery_url):
        jwks = JWKS(discovery_url, jwks_uri="https://example.com/jwks")
        assert jwks._discovery_url == discovery_url
        assert jwks._jwks_uri == "https://example.com/jwks"

    def test_init_neither_raises(self):
        with pytest.raises(ValueError, match="Either.*discovery_url.*jwks_uri"):
            JWKS()

    def test_init_jwks_uri_with_issuer(self):
        jwks = JWKS(jwks_uri="https://example.com/jwks", issuer="https://issuer.example.com")
        assert jwks._issuer == "https://issuer.example.com"
        assert jwks._jwks_uri == "https://example.com/jwks"

    def test_init_discovery_url_with_issuer_raises(self, discovery_url):
        with pytest.raises(ValueError, match="'issuer' cannot be used with 'discovery_url' alone"):
            JWKS(discovery_url, issuer="https://custom.issuer.com")

    def test_init_both_urls_with_issuer_allowed(self, discovery_url):
        jwks = JWKS(
            discovery_url, jwks_uri="https://example.com/jwks", issuer="https://custom.issuer.com"
        )
        assert jwks._issuer == "https://custom.issuer.com"

    def test_normalize_url_fixes_scheme(self, discovery_url):
        jwks = JWKS(discovery_url)
        fixed = jwks._normalize_url("http://different.host/jwks")
        assert fixed.startswith("https://")
        assert "issuer.example.com" in fixed

    def test_normalize_url_disabled(self, discovery_url):
        jwks = JWKS(discovery_url, fix_local_url=False)
        url = "http://internal-host/jwks"
        assert jwks._normalize_url(url) == url

    async def test_refresh_fetches_keys(self, jwk, httpx_mock, discovery_url):
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

    async def test_refresh_direct_jwks_uri_single_http_call(self, jwk, httpx_mock):
        """_refresh() with jwks_uri only fetches keys directly (single HTTP call, no discovery)."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )

        jwks_client = JWKS(jwks_uri=jwks_uri, issuer="https://example.com")
        keys = await jwks_client._refresh()
        assert "test-kid" in keys
        assert keys["test-kid"].alg == "RS256"
        # Only one HTTP request should have been made (no discovery)
        assert len(httpx_mock.get_requests()) == 1
        assert httpx_mock.get_requests()[0].url == jwks_uri
        await jwks_client.close()

    async def test_refresh_direct_jwks_uri_with_explicit_issuer(self, jwk, httpx_mock):
        """_refresh() with jwks_uri + explicit issuer sets correct issuer on keys."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )

        jwks_client = JWKS(jwks_uri=jwks_uri, issuer="https://my-issuer.example.com")
        keys = await jwks_client._refresh()
        assert keys["test-kid"].issuer == "https://my-issuer.example.com"
        await jwks_client.close()

    async def test_refresh_direct_jwks_uri_without_issuer(self, jwk, httpx_mock):
        """_refresh() with jwks_uri without issuer sets None issuer on keys."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )

        jwks_client = JWKS(jwks_uri=jwks_uri)
        keys = await jwks_client._refresh()
        assert keys["test-kid"].issuer is None
        await jwks_client.close()

    async def test_refresh_discovery_mode_still_works(self, jwk, httpx_mock, discovery_url):
        """_refresh() with discovery_url still works as before (existing behavior)."""
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
        assert keys["test-kid"].issuer == "https://issuer.example.com"
        # Two HTTP requests: discovery + jwks fetch
        assert len(httpx_mock.get_requests()) == 2
        await jwks_client.close()

    async def test_verify_token_direct_jwks_uri_with_issuer(self, rsa_key, jwk, httpx_mock):
        """verify_token() succeeds with direct jwks_uri + matching issuer."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )

        token = _make_signed_token(rsa_key, payload={"iss": "https://example.com"})
        jwks_client = JWKS(
            jwks_uri=jwks_uri,
            issuer="https://example.com",
            aud="test-audience",
            leeway=60,
        )
        payload = await jwks_client.verify_token(token)
        assert payload["sub"] == "user-123"
        assert payload["iss"] == "https://example.com"
        await jwks_client.close()

    async def test_verify_token_direct_jwks_uri_without_issuer(self, rsa_key, jwk, httpx_mock):
        """verify_token() succeeds with direct jwks_uri without issuer."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )

        token = _make_signed_token(rsa_key)
        jwks_client = JWKS(jwks_uri=jwks_uri, aud="test-audience", leeway=60)
        payload = await jwks_client.verify_token(token)
        assert payload["sub"] == "user-123"
        # issuer in token is not validated against any expected value
        assert payload["iss"] == "https://issuer.example.com"
        await jwks_client.close()

    async def test_verify_token_direct_jwks_uri_wrong_issuer_rejected(
        self, rsa_key, jwk, httpx_mock
    ):
        """verify_token() rejects token when issuer does not match configured issuer."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )

        token = _make_signed_token(rsa_key, payload={"iss": "https://evil.example.com"})
        jwks_client = JWKS(
            jwks_uri=jwks_uri,
            issuer="https://example.com",
            aud="test-audience",
            leeway=60,
        )
        with pytest.raises(pyjwt.InvalidTokenError):
            await jwks_client.verify_token(token)
        await jwks_client.close()

    async def test_verify_token_direct_jwks_uri_bearer_prefix(self, rsa_key, jwk, httpx_mock):
        """verify_token() strips Bearer prefix in direct jwks_uri mode."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )

        token = _make_signed_token(rsa_key)
        jwks_client = JWKS(jwks_uri=jwks_uri, aud="test-audience", leeway=60)
        payload = await jwks_client.verify_token(f"Bearer {token}")
        assert payload["sub"] == "user-123"
        await jwks_client.close()

    async def test_refresh_direct_jwks_uri_http_error(self, httpx_mock):
        """_refresh() raises on HTTP error from jwks_uri endpoint."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(url=jwks_uri, status_code=500)

        jwks_client = JWKS(jwks_uri=jwks_uri)
        with pytest.raises(httpx.HTTPStatusError):
            await jwks_client._refresh()
        await jwks_client.close()

    async def test_refresh_direct_jwks_uri_empty_keys(self, rsa_key, httpx_mock):
        """verify_token() fails when jwks_uri returns no usable keys."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": []},
        )

        token = _make_signed_token(rsa_key)
        jwks_client = JWKS(jwks_uri=jwks_uri, aud="test-audience", leeway=60)
        with pytest.raises(pyjwt.InvalidTokenError):
            await jwks_client.verify_token(token)
        await jwks_client.close()

    async def test_refresh_direct_jwks_uri_precedence_over_discovery(
        self, jwk, httpx_mock, discovery_url
    ):
        """When both discovery_url and jwks_uri are provided, only jwks_uri is fetched."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )
        # No mock for discovery_url -- if it's fetched, httpx_mock will raise

        jwks_client = JWKS(discovery_url, jwks_uri=jwks_uri, issuer="https://example.com")
        keys = await jwks_client._refresh()
        assert "test-kid" in keys
        assert len(httpx_mock.get_requests()) == 1
        assert httpx_mock.get_requests()[0].url == jwks_uri
        await jwks_client.close()

    async def test_verify_token_both_urls_no_issuer_skips_iss_validation(
        self, rsa_key, jwk, httpx_mock, discovery_url
    ):
        """When both discovery_url and jwks_uri are provided without explicit issuer,
        issuer validation is skipped (consistent with pure direct mode).
        Uses a token WITHOUT iss to prove the claim is not required."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )

        # Token without iss — if iss validation were active, this would fail
        now = datetime.now(timezone.utc)
        no_iss_payload = {
            "sub": "user-123",
            "aud": "test-audience",
            "exp": now + timedelta(hours=1),
            "iat": now,
        }
        token = pyjwt.encode(
            no_iss_payload, rsa_key, algorithm="RS256", headers={"kid": "test-kid"}
        )
        jwks_client = JWKS(discovery_url, jwks_uri=jwks_uri, aud="test-audience", leeway=60)
        payload = await jwks_client.verify_token(token, verify_iss=False)
        assert payload["sub"] == "user-123"
        assert "iss" not in payload
        await jwks_client.close()

    async def test_close(self, discovery_url):
        jwks_client = JWKS(discovery_url)
        await jwks_client.close()
        assert jwks_client._client is None
        # closing twice should not raise
        await jwks_client.close()
