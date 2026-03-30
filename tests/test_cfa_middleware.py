from unittest.mock import AsyncMock

from starlette.requests import Request
from starlette.responses import Response

from auth_jwks.cloudflare.client import User
from auth_jwks.cloudflare.middleware import CfaAuthMiddleware


def _make_request(
    headers: dict | None = None,
    cookies: dict | None = None,
) -> Request:
    header_list = []
    if headers:
        for k, v in headers.items():
            header_list.append((k.lower().encode(), v.encode()))
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        header_list.append((b"cookie", cookie_str.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/admin/ui/",
        "headers": header_list,
        "query_string": b"",
    }
    return Request(scope)


def _make_middleware(verify_token=None, **kwargs) -> CfaAuthMiddleware:
    return CfaAuthMiddleware(AsyncMock(), verify_token=verify_token, **kwargs)


class TestCfaAuthMiddlewareDevMode:
    async def test_dev_mode_sets_dev_user_and_calls_next(self):
        middleware = _make_middleware(dev_user=User(sub="dev-sub", email="dev@example.com"))
        request = _make_request()
        next_response = Response("ok", status_code=200)
        call_next = AsyncMock(return_value=next_response)

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        assert request.state.user == User(sub="dev-sub", email="dev@example.com")
        call_next.assert_called_once_with(request)

    async def test_no_dev_user_falls_through_to_token_check(self):
        middleware = _make_middleware()
        request = _make_request()
        call_next = AsyncMock()

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 401
        call_next.assert_not_called()


class TestCfaAuthMiddlewareProdMode:
    async def test_no_token_returns_401(self):
        middleware = _make_middleware()
        request = _make_request()
        call_next = AsyncMock()

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 401
        assert response.body == b'{"detail":"Invalid CFA Token"}'
        call_next.assert_not_called()

    async def test_valid_header_token_sets_user_and_calls_next(self):
        verified_user = User(sub="real-sub", email="real@example.com")
        verify_token = AsyncMock(return_value=verified_user)
        middleware = _make_middleware(verify_token=verify_token)
        request = _make_request(headers={"Cf-Access-Jwt-Assertion": "valid-token"})
        next_response = Response("ok", status_code=200)
        call_next = AsyncMock(return_value=next_response)

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        assert request.state.user == verified_user
        verify_token.assert_called_once_with("valid-token")
        call_next.assert_called_once_with(request)

    async def test_verify_user_raises_returns_401(self):
        verify_token = AsyncMock(side_effect=Exception("token invalid"))
        middleware = _make_middleware(verify_token=verify_token)
        request = _make_request(headers={"Cf-Access-Jwt-Assertion": "bad-token"})
        call_next = AsyncMock()

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 401
        assert response.body == b'{"detail":"CFA token verification failed"}'
        call_next.assert_not_called()

    async def test_cookie_token_used_when_header_absent(self):
        verified_user = User(sub="cookie-sub", email="cookie@example.com")
        verify_token = AsyncMock(return_value=verified_user)
        middleware = _make_middleware(verify_token=verify_token)
        request = _make_request(cookies={"CF_Authorization": "cookie-token"})
        next_response = Response("ok", status_code=200)
        call_next = AsyncMock(return_value=next_response)

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        verify_token.assert_called_once_with("cookie-token")

    async def test_custom_header_name(self):
        verified_user = User(sub="sub", email="e@e.com")
        verify_token = AsyncMock(return_value=verified_user)
        middleware = _make_middleware(verify_token=verify_token, header_name="X-Custom-Token")
        request = _make_request(headers={"X-Custom-Token": "my-token"})
        next_response = Response("ok", status_code=200)
        call_next = AsyncMock(return_value=next_response)

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        verify_token.assert_called_once_with("my-token")

    async def test_custom_cookie_name(self):
        verified_user = User(sub="sub", email="e@e.com")
        verify_token = AsyncMock(return_value=verified_user)
        middleware = _make_middleware(verify_token=verify_token, cookie_name="MY_COOKIE")
        request = _make_request(cookies={"MY_COOKIE": "cookie-val"})
        next_response = Response("ok", status_code=200)
        call_next = AsyncMock(return_value=next_response)

        response = await middleware.dispatch(request, call_next)

        assert response.status_code == 200
        verify_token.assert_called_once_with("cookie-val")
