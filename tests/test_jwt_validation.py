import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import auth_jwks
from auth_jwks.jwt_validation import JWKS, IssuerMismatchError


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

    def test_init_discovery_url_with_issuer_no_longer_raises(self, discovery_url):
        jwks = JWKS(discovery_url, issuer="https://explicit.example.com")
        assert jwks._issuer == "https://explicit.example.com"

    def test_init_discovery_only_logs_warning(self, discovery_url, caplog):
        with caplog.at_level(logging.WARNING, logger="auth_jwks.jwt_validation"):
            JWKS(discovery_url)
        defence_warnings = [
            r
            for r in caplog.records
            if "defence-in-depth" in r.message and r.levelno == logging.WARNING
        ]
        assert len(defence_warnings) == 1

    def test_init_discovery_with_issuer_does_not_log_warning(self, discovery_url, caplog):
        with caplog.at_level(logging.WARNING, logger="auth_jwks.jwt_validation"):
            JWKS(discovery_url, issuer="https://explicit.example.com")
        assert not any("defence-in-depth" in record.message for record in caplog.records)

    def test_init_direct_mode_without_issuer_logs_warning(self, caplog):
        with caplog.at_level(logging.WARNING, logger="auth_jwks.jwt_validation"):
            JWKS(jwks_uri="https://example.com/jwks")
        issuer_warnings = [
            r
            for r in caplog.records
            if "issuer" in r.message.lower() and r.levelno == logging.WARNING
        ]
        assert len(issuer_warnings) == 1

    def test_init_both_urls_no_issuer_emits_direct_mode_warning(self, discovery_url, caplog):
        """When both discovery_url and jwks_uri are given without issuer=,
        the direct-mode warning fires (jwks_uri takes precedence, issuer validation is skipped)
        but the discovery defence-in-depth warning does NOT fire."""
        with caplog.at_level(logging.WARNING, logger="auth_jwks.jwt_validation"):
            JWKS(discovery_url, jwks_uri="https://example.com/jwks")
        issuer_warnings = [
            r
            for r in caplog.records
            if "issuer claim validation" in r.message and r.levelno == logging.WARNING
        ]
        assert len(issuer_warnings) == 1
        assert not any("defence-in-depth" in record.message for record in caplog.records)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"discovery_url": "https://issuer.example.com/.well-known/openid-configuration"},
            {"jwks_uri": "https://example.com/jwks"},
        ],
    )
    @pytest.mark.parametrize("bad_issuer", ["", "   "])
    def test_init_empty_issuer_raises(self, kwargs, bad_issuer):
        with pytest.raises(ValueError, match="'issuer' must be a non-empty string or None"):
            JWKS(**kwargs, issuer=bad_issuer)

    def test_init_both_urls_with_issuer_allowed(self, discovery_url):
        jwks = JWKS(
            discovery_url, jwks_uri="https://example.com/jwks", issuer="https://custom.issuer.com"
        )
        assert jwks._issuer == "https://custom.issuer.com"

    def test_issuer_mismatch_error_is_invalid_token_error_subclass(self):
        assert issubclass(IssuerMismatchError, pyjwt.InvalidTokenError) is True

    def test_issuer_mismatch_error_importable_from_package(self):
        assert hasattr(auth_jwks, "IssuerMismatchError")
        assert auth_jwks.IssuerMismatchError is IssuerMismatchError

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

    async def test_refresh_with_matching_issuer_uses_configured_value(
        self, jwk, httpx_mock, discovery_url
    ):
        """discovery returns iss=X, construct with issuer=X → keys carry issuer=X."""
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

        jwks_client = JWKS(discovery_url, issuer="https://issuer.example.com")
        keys = await jwks_client._refresh()
        assert keys["test-kid"].issuer == "https://issuer.example.com"
        await jwks_client.close()

    async def test_refresh_with_mismatched_issuer_raises_issuer_mismatch_error(
        self, jwk, httpx_mock, discovery_url
    ):
        """discovery returns iss=X, construct with issuer=Y → IssuerMismatchError raised."""
        httpx_mock.add_response(
            url=discovery_url,
            json={
                "issuer": "https://issuer.example.com",
                "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
            },
        )

        jwks_client = JWKS(discovery_url, issuer="https://other-issuer.example.com")
        with pytest.raises(IssuerMismatchError) as exc_info:
            await jwks_client._refresh()
        # Must also be catchable as jwt.InvalidTokenError
        assert isinstance(exc_info.value, pyjwt.InvalidTokenError)
        # Error message must mention both values
        assert "https://issuer.example.com" in str(exc_info.value)
        assert "https://other-issuer.example.com" in str(exc_info.value)
        # Only discovery request made — mismatch raised before JWKS fetch
        assert len(httpx_mock.get_requests()) == 1
        await jwks_client.close()

    async def test_refresh_without_explicit_issuer_uses_discovery_value(
        self, jwk, httpx_mock, discovery_url
    ):
        """Backward compat: discovery returns iss=X, no issuer= → keys carry issuer=X."""
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

        jwks_client = JWKS(discovery_url)
        keys = await jwks_client._refresh()
        assert keys["test-kid"].issuer == "https://issuer.example.com"
        await jwks_client.close()

    async def test_refresh_mismatch_does_not_poison_cache(
        self, rsa_key, jwk, httpx_mock, discovery_url
    ):
        """After a mismatch error, cache remains empty and expiry not advanced.

        Uses verify_token() (the real execution path: get_key → _refresh) rather than calling
        _refresh() directly, so any future regression that updates cache inside get_key() before
        the exception propagates will be caught.
        """
        httpx_mock.add_response(
            url=discovery_url,
            json={
                "issuer": "https://issuer.example.com",
                "jwks_uri": "https://issuer.example.com/.well-known/jwks.json",
            },
        )

        token = _make_signed_token(rsa_key)
        jwks_client = JWKS(
            discovery_url,
            issuer="https://wrong-issuer.example.com",
            aud="test-audience",
            leeway=60,
        )
        # Confirm initial state: _expires_at starts at 0.0 (never refreshed)
        assert jwks_client._expires_at == 0.0
        with pytest.raises(IssuerMismatchError):
            await jwks_client.verify_token(token)
        # Cache must still be empty — mismatch must not have populated keys
        assert jwks_client._keys_by_kid == {}
        # expiry must remain at 0.0 — not advanced to a future value
        assert jwks_client._expires_at == 0.0
        await jwks_client.close()

    async def test_refresh_both_urls_skips_discovery_mismatch_check(
        self, jwk, httpx_mock, discovery_url
    ):
        """When both discovery_url and jwks_uri are set, _refresh() uses direct mode only.
        Discovery endpoint must NOT be called even if it would return a mismatched issuer."""
        jwks_uri = "https://example.com/.well-known/jwks.json"
        httpx_mock.add_response(
            url=jwks_uri,
            json={"keys": [jwk]},
        )
        # No mock for discovery_url — any request to it would raise in httpx_mock

        jwks_client = JWKS(
            discovery_url,
            jwks_uri=jwks_uri,
            issuer="https://configured.example.com",
        )
        keys = await jwks_client._refresh()
        assert "test-kid" in keys
        assert keys["test-kid"].issuer == "https://configured.example.com"
        # Only one HTTP request made — the direct jwks_uri fetch
        requests = httpx_mock.get_requests()
        assert len(requests) == 1
        assert str(requests[0].url) == jwks_uri
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
        with pytest.raises(pyjwt.InvalidIssuerError):
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

    async def test_verify_token_both_urls_no_issuer_skips_iss_validation(
        self, rsa_key, jwk, httpx_mock, discovery_url
    ):
        """When both discovery_url and jwks_uri are provided without explicit issuer,
        effective_verify_iss defaults to False (consistent with pure direct mode).
        verify_iss defaults to True — the effective behaviour is derived internally.
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
        # verify_iss left at default True — effective_verify_iss=False because jwks_uri
        # is set and issuer=None, so iss is not required and the token passes validation
        payload = await jwks_client.verify_token(token)
        assert payload["sub"] == "user-123"
        assert "iss" not in payload
        await jwks_client.close()

    async def test_verify_token_discovery_with_matching_issuer_success(
        self, rsa_key, jwk, httpx_mock, discovery_url
    ):
        """Full path: discovery + matching issuer= + signed token with iss=X validates
        successfully."""
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

        token = _make_signed_token(rsa_key)  # iss="https://issuer.example.com"
        jwks_client = JWKS(
            discovery_url,
            issuer="https://issuer.example.com",
            aud="test-audience",
            leeway=60,
        )
        payload = await jwks_client.verify_token(token)
        assert payload["sub"] == "user-123"
        assert payload["iss"] == "https://issuer.example.com"
        await jwks_client.close()

    async def test_verify_token_discovery_with_mismatched_issuer_raises(
        self, rsa_key, jwk, httpx_mock, discovery_url
    ):
        """Full path: discovery returns iss=X, configured issuer=Y → IssuerMismatchError raised.
        Confirms that the subclass propagates cleanly through base._verify_token
        exception handling."""
        httpx_mock.add_response(
            url=discovery_url,
            json={
                "issuer": "https://issuer.example.com",
                "jwks_uri": "https://issuer.example.com/jwks",
            },
        )

        token = _make_signed_token(rsa_key)
        jwks_client = JWKS(
            discovery_url,
            issuer="https://other-issuer.example.com",
            aud="test-audience",
            leeway=60,
        )
        with pytest.raises(IssuerMismatchError) as exc_info:
            await jwks_client.verify_token(token)
        # Must also be catchable as jwt.InvalidTokenError
        assert isinstance(exc_info.value, pyjwt.InvalidTokenError)
        await jwks_client.close()

    async def test_verify_token_discovery_only_backward_compat(
        self, rsa_key, jwk, httpx_mock, discovery_url
    ):
        """No explicit issuer=, token with iss matching discovery validates successfully.
        Regression: ensures no behaviour change for existing consumers."""
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

        token = _make_signed_token(rsa_key)  # iss="https://issuer.example.com"
        jwks_client = JWKS(discovery_url, aud="test-audience", leeway=60)
        payload = await jwks_client.verify_token(token)
        assert payload["sub"] == "user-123"
        assert payload["iss"] == "https://issuer.example.com"
        await jwks_client.close()

    async def test_verify_token_discovery_only_rejects_token_with_foreign_iss(
        self, rsa_key, jwk, httpx_mock, discovery_url
    ):
        """No explicit issuer=, signed token has iss that does NOT match discovery's issuer.
        verify_token raises jwt.InvalidIssuerError (PyJWT native exception).
        Regression guard: ensures discovery-only mode still validates iss against
        discovery's value."""
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

        token = _make_signed_token(rsa_key, payload={"iss": "https://foreign-issuer.example.com"})
        jwks_client = JWKS(discovery_url, aud="test-audience", leeway=60)
        with pytest.raises(pyjwt.InvalidIssuerError):
            await jwks_client.verify_token(token)
        await jwks_client.close()

    async def test_close(self, discovery_url):
        jwks_client = JWKS(discovery_url)
        await jwks_client.close()
        assert jwks_client._client is None
        # closing twice should not raise
        await jwks_client.close()
