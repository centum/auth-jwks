import json
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from auth_jwks.cloudflare.client import CloudFlareTokenValidation, Identity, User


def _generate_rsa_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _make_jwk(private_key, kid="test-kid", alg="RS256"):
    public_key = private_key.public_key()
    from jwt.algorithms import RSAAlgorithm

    jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = kid
    jwk_dict["alg"] = alg
    jwk_dict["use"] = "sig"
    return jwk_dict


def _make_signed_token(private_key, kid="test-kid", alg="RS256", payload=None):
    now = datetime.now(timezone.utc)
    default_payload = {
        "sub": "user-123",
        "iss": "https://testteam.cloudflareaccess.com",
        "aud": "test-aud",
        "exp": now + timedelta(hours=1),
        "iat": now,
        "email": "user@example.com",
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
def cfa_client():
    return CloudFlareTokenValidation(aud="test-aud", team="testteam")


class TestCloudFlareTokenValidationInit:
    def test_init(self):
        client = CloudFlareTokenValidation(aud="test-aud", team="testteam")
        assert client.aud == "test-aud"
        assert client.issuer == "https://testteam.cloudflareaccess.com"
        assert client.cert_url == "https://testteam.cloudflareaccess.com/cdn-cgi/access/certs"
        assert (
            client.identity_url
            == "https://testteam.cloudflareaccess.com/cdn-cgi/access/get-identity"
        )

    def test_default_algorithms(self):
        client = CloudFlareTokenValidation(aud="test-aud", team="testteam")
        assert "RS256" in client._allowed_algorithms
        assert "ES256" in client._allowed_algorithms

    def test_custom_algorithms(self):
        client = CloudFlareTokenValidation(
            aud="test-aud", team="testteam", allowed_algorithms={"RS256"}
        )
        assert client._allowed_algorithms == {"RS256"}


class TestCloudFlareTokenValidationClose:
    async def test_close(self):
        client = CloudFlareTokenValidation(aud="test-aud", team="testteam")
        await client.close()
        assert client._client is None

    async def test_close_twice(self):
        client = CloudFlareTokenValidation(aud="test-aud", team="testteam")
        await client.close()
        # should not raise
        await client.close()


class TestCloudFlareTokenValidationRefresh:
    async def test_refresh_fetches_keys(self, rsa_key, jwk, httpx_mock, cfa_client):
        httpx_mock.add_response(
            url=cfa_client.cert_url,
            json={"keys": [jwk]},
        )
        keys = await cfa_client._refresh()
        assert "test-kid" in keys
        assert keys["test-kid"].alg == "RS256"
        assert keys["test-kid"].issuer == cfa_client.issuer
        await cfa_client.close()

    async def test_refresh_skips_unsupported_algorithms(self, httpx_mock, cfa_client):
        httpx_mock.add_response(
            url=cfa_client.cert_url,
            json={"keys": [{"kid": "k1", "alg": "PS256", "kty": "RSA"}]},
        )
        keys = await cfa_client._refresh()
        assert len(keys) == 0
        await cfa_client.close()

    async def test_refresh_after_close_raises(self):
        client = CloudFlareTokenValidation(aud="test-aud", team="testteam")
        await client.close()
        with pytest.raises(RuntimeError, match="Client is closed"):
            await client._refresh()


class TestCloudFlareTokenValidationVerifyToken:
    async def test_verify_token_success(self, rsa_key, jwk, httpx_mock, cfa_client):
        httpx_mock.add_response(url=cfa_client.cert_url, json={"keys": [jwk]})
        token = _make_signed_token(rsa_key)
        payload = await cfa_client.verify_token(token)
        assert payload["sub"] == "user-123"
        assert payload["email"] == "user@example.com"
        await cfa_client.close()

    async def test_verify_token_with_bearer_prefix(self, rsa_key, jwk, httpx_mock, cfa_client):
        httpx_mock.add_response(url=cfa_client.cert_url, json={"keys": [jwk]})
        token = _make_signed_token(rsa_key)
        payload = await cfa_client.verify_token(f"Bearer {token}")
        assert payload["sub"] == "user-123"
        await cfa_client.close()

    async def test_verify_token_wrong_audience_raises(self, rsa_key, jwk, httpx_mock):
        client = CloudFlareTokenValidation(aud="wrong-aud", team="testteam")
        httpx_mock.add_response(url=client.cert_url, json={"keys": [jwk]})
        token = _make_signed_token(rsa_key)
        with pytest.raises(pyjwt.InvalidTokenError):
            await client.verify_token(token)
        await client.close()

    async def test_verify_token_expired_raises(self, rsa_key, jwk, httpx_mock, cfa_client):
        httpx_mock.add_response(url=cfa_client.cert_url, json={"keys": [jwk]})
        expired = datetime.now(timezone.utc) - timedelta(hours=1)
        token = _make_signed_token(rsa_key, payload={"exp": expired})
        with pytest.raises(pyjwt.InvalidTokenError):
            await cfa_client.verify_token(token)
        await cfa_client.close()


class TestCloudFlareTokenValidationVerifyEmail:
    async def test_verify_email_returns_email(self, rsa_key, jwk, httpx_mock, cfa_client):
        httpx_mock.add_response(url=cfa_client.cert_url, json={"keys": [jwk]})
        token = _make_signed_token(rsa_key)
        email = await cfa_client.verify_email(token)
        assert email == "user@example.com"
        await cfa_client.close()


class TestCloudFlareTokenValidationVerifyUser:
    async def test_verify_user_returns_user(self, rsa_key, jwk, httpx_mock, cfa_client):
        httpx_mock.add_response(url=cfa_client.cert_url, json={"keys": [jwk]})
        token = _make_signed_token(rsa_key, payload={"country": "US"})
        user = await cfa_client.verify_user(token)
        assert isinstance(user, User)
        assert user.sub == "user-123"
        assert user.email == "user@example.com"
        assert user.country == "US"
        assert user.exists_identity is False
        await cfa_client.close()

    async def test_verify_user_with_identity_nonce(self, rsa_key, jwk, httpx_mock, cfa_client):
        httpx_mock.add_response(url=cfa_client.cert_url, json={"keys": [jwk]})
        token = _make_signed_token(rsa_key, payload={"identity_nonce": "nonce-123"})
        user = await cfa_client.verify_user(token)
        assert user.exists_identity is True
        await cfa_client.close()


class TestCloudFlareTokenValidationGetIdentity:
    async def test_get_identity_returns_identity(self, httpx_mock, cfa_client):
        httpx_mock.add_response(
            url=cfa_client.identity_url,
            json={
                "email": "user@example.com",
                "user_uuid": "uuid-123",
                "account_id": "acc-456",
                "iat": 1700000000,
                "ip": "1.2.3.4",
                "auth_status": "NONE",
                "cn": "user",
                "is_warp": False,
                "is_gateway": False,
                "devicePosture": {"posture-id": {"check": {"passed": True}}},
            },
        )
        identity = await cfa_client.get_identity("cf-token")
        assert isinstance(identity, Identity)
        assert identity.email == "user@example.com"
        assert identity.user_uuid == "uuid-123"
        assert identity.account_id == "acc-456"
        assert identity.ip == "1.2.3.4"
        assert identity.common_name == "user"
        assert identity.device_posture == {"posture-id": {"check": {"passed": True}}}
        await cfa_client.close()

    async def test_get_identity_after_close_raises(self):
        client = CloudFlareTokenValidation(aud="test-aud", team="testteam")
        await client.close()
        with pytest.raises(RuntimeError, match="Client is closed"):
            await client.get_identity("cf-token")
