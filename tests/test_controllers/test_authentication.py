"""
Unit tests for the OIDC-aware bearer-token verifier in
``FreeTAKServer.services.rest_api_service.controllers.authentication``.

These tests:
  * generate an RSA keypair in-memory each test
  * sign synthetic JWT claims with that key
  * monkey-patch ``_fetch_jwks`` to return the matching public key
  * stub ``dbController`` with a fake systemUser store
  * exercise verify_token() through Flask's request context

No network, no filesystem.
"""

import time
from types import SimpleNamespace
from unittest import mock

import pytest


@pytest.fixture
def rsa_keypair():
    """Generate an RSA keypair as a JWK in-memory."""
    from authlib.jose.rfc7517 import JsonWebKey
    private = JsonWebKey.generate_key(
        kty='RSA', crv_or_size=2048, is_private=True,
        options={'kid': 'test-kid-1'},
    )
    return private


def _make_jwt(claims, jwk):
    from authlib.jose import jwt
    header = {'alg': 'RS256', 'typ': 'JWT', 'kid': jwk.as_dict().get('kid', 'test-kid-1')}
    return jwt.encode(header, claims, jwk).decode('ascii')


@pytest.fixture
def mock_config():
    """A MainConfig-like object with OIDC settings."""
    return SimpleNamespace(
        OIDCIssuer='https://idp.example.com',
        OIDCAudience='fts-api',
        OIDCRequiredScope='',
        OIDCUsernameClaim='preferred_username',
    )


@pytest.fixture
def patched_auth(rsa_keypair, mock_config):
    """Patch the auth module: JWKS lookups return our keypair, MainConfig
    returns ``mock_config``."""
    from authlib.jose.rfc7517 import JsonWebKey
    from FreeTAKServer.services.rest_api_service.controllers import authentication as auth_mod

    public_jwk = JsonWebKey.import_key(rsa_keypair.as_dict())
    keyset = JsonWebKey.import_key_set([public_jwk.as_dict()])

    with mock.patch.object(auth_mod, '_fetch_jwks', return_value=keyset), \
         mock.patch.object(auth_mod.MainConfig, 'instance', return_value=mock_config):
        yield auth_mod


def _now():
    # Use epoch directly; datetime.utcnow() naive + .timestamp() can drift
    # the wrong direction relative to UTC and trip "iat in future" checks.
    return int(time.time())


def test_verify_jwt_accepts_valid_token(patched_auth, rsa_keypair, mock_config):
    claims = {
        'iss': mock_config.OIDCIssuer,
        'aud': mock_config.OIDCAudience,
        'sub': 'user-1',
        'preferred_username': 'alice',
        'iat': _now(),
        'exp': _now() + 300,
    }
    token = _make_jwt(claims, rsa_keypair)
    decoded = patched_auth._verify_jwt(token, mock_config)
    assert decoded['preferred_username'] == 'alice'


def test_verify_jwt_rejects_wrong_issuer(patched_auth, rsa_keypair, mock_config):
    claims = {
        'iss': 'https://attacker.example.com',
        'aud': mock_config.OIDCAudience,
        'sub': 'user-1', 'iat': _now(), 'exp': _now() + 300,
    }
    token = _make_jwt(claims, rsa_keypair)
    with pytest.raises(Exception):
        patched_auth._verify_jwt(token, mock_config)


def test_verify_jwt_rejects_expired_token(patched_auth, rsa_keypair, mock_config):
    claims = {
        'iss': mock_config.OIDCIssuer,
        'aud': mock_config.OIDCAudience,
        'sub': 'user-1', 'iat': _now() - 600, 'exp': _now() - 300,
    }
    token = _make_jwt(claims, rsa_keypair)
    with pytest.raises(Exception):
        patched_auth._verify_jwt(token, mock_config)


def test_verify_jwt_rejects_wrong_audience(patched_auth, rsa_keypair, mock_config):
    claims = {
        'iss': mock_config.OIDCIssuer,
        'aud': 'someone-else',
        'sub': 'user-1', 'iat': _now(), 'exp': _now() + 300,
    }
    token = _make_jwt(claims, rsa_keypair)
    with pytest.raises(Exception):
        patched_auth._verify_jwt(token, mock_config)


def test_verify_jwt_enforces_required_scope(patched_auth, rsa_keypair, mock_config):
    mock_config.OIDCRequiredScope = 'fts:api'
    claims = {
        'iss': mock_config.OIDCIssuer,
        'aud': mock_config.OIDCAudience,
        'sub': 'user-1', 'iat': _now(), 'exp': _now() + 300,
        'scope': 'openid profile',  # missing fts:api
    }
    token = _make_jwt(claims, rsa_keypair)
    with pytest.raises(Exception):
        patched_auth._verify_jwt(token, mock_config)

    claims['scope'] = 'openid profile fts:api'
    token = _make_jwt(claims, rsa_keypair)
    decoded = patched_auth._verify_jwt(token, mock_config)
    assert 'fts:api' in decoded['scope']


def test_looks_like_jwt():
    from FreeTAKServer.services.rest_api_service.controllers import authentication as auth_mod
    assert auth_mod._looks_like_jwt('a.b.c') is True
    assert auth_mod._looks_like_jwt('static-token') is False
    assert auth_mod._looks_like_jwt('a.b') is False
    assert auth_mod._looks_like_jwt('') is False
    assert auth_mod._looks_like_jwt(None) is False


def test_verify_token_falls_back_to_legacy_for_static_tokens(patched_auth):
    """A non-JWT bearer should hit the legacy DB lookup even when OIDC
    is enabled. Existing static API tokens must keep working."""
    from flask import Flask
    fake_user = SimpleNamespace(Username='legacy-user', uid='u1', name='legacy-user')
    fake_db = SimpleNamespace(
        query_APIUser=mock.Mock(return_value=[fake_user]),
        query_systemUser=mock.Mock(return_value=[]),
        create_APICall=mock.Mock(),
    )
    fake_persistency = SimpleNamespace(dbController=fake_db)
    with mock.patch.dict(
        'sys.modules',
        {'FreeTAKServer.services.rest_api_service.controllers.persistency': fake_persistency},
    ):
        app = Flask(__name__)
        with app.test_request_context('/test', method='GET'):
            result = patched_auth.verify_token('plain-static-token')
    assert result == 'legacy-user'
    fake_db.query_APIUser.assert_called_once()


def test_verify_token_rejects_bad_jwt_without_legacy_fallback(patched_auth):
    """A JWT-shaped bearer that fails validation must NOT fall through
    to the static-token lookup. Otherwise an attacker could probe stored
    API tokens by sending forged JWTs."""
    from flask import Flask
    fake_db = SimpleNamespace(
        query_APIUser=mock.Mock(return_value=[]),
        query_systemUser=mock.Mock(return_value=[]),
        create_APICall=mock.Mock(),
    )
    fake_persistency = SimpleNamespace(dbController=fake_db)
    bogus_jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.bogus-signature'
    with mock.patch.dict(
        'sys.modules',
        {'FreeTAKServer.services.rest_api_service.controllers.persistency': fake_persistency},
    ):
        app = Flask(__name__)
        with app.test_request_context('/test', method='GET'):
            result = patched_auth.verify_token(bogus_jwt)
    assert result is None
    fake_db.query_APIUser.assert_not_called()
    fake_db.query_systemUser.assert_not_called()
