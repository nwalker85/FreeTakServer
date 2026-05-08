"""
Bearer-token authentication for the FreeTAKServer REST API.

The default flow continues to look up tokens in the ``APIUser`` and
``systemUser`` tables. When ``OIDCIssuer`` is set in MainConfig the
verifier first attempts to validate the token as an OIDC-issued JWT
against the issuer's JWKS; on a successful validation the matching
``systemUser`` (by name claim) is returned. If the bearer is shaped
like a JWT but fails validation the request is rejected outright --
falling back to the DB lookup in that case would let an attacker craft
a malformed JWT to probe stored static tokens.

Configured via env vars (see MainConfig):
    FTS_OIDC_ISSUER, FTS_OIDC_AUDIENCE,
    FTS_OIDC_REQUIRED_SCOPE, FTS_OIDC_USERNAME_CLAIM
"""

import datetime as dt
import logging
import threading
import time
from typing import Optional

from flask import request
from flask_httpauth import HTTPTokenAuth

from FreeTAKServer.core.configuration.MainConfig import MainConfig

logger = logging.getLogger(__name__)

auth = HTTPTokenAuth(scheme='Bearer')

# JWKS / discovery cache. Keyed by issuer so reconfiguration without a
# restart still works in tests.
_JWKS_TTL_SEC = 3600
_jwks_cache = {"issuer": None, "keys": None, "fetched_at": 0.0}
_jwks_lock = threading.Lock()


class _NotAJWT(Exception):
    """Raised when the bearer doesn't look like a JWT at all."""


def _looks_like_jwt(token: str) -> bool:
    return isinstance(token, str) and token.count('.') == 2


def _fetch_jwks(issuer: str):
    """Discover and cache the JWKS for ``issuer`` (TTL ``_JWKS_TTL_SEC``)."""
    import requests
    from authlib.jose.rfc7517 import JsonWebKey

    with _jwks_lock:
        now = time.time()
        if (
            _jwks_cache["issuer"] == issuer
            and _jwks_cache["keys"] is not None
            and (now - _jwks_cache["fetched_at"]) < _JWKS_TTL_SEC
        ):
            return _jwks_cache["keys"]
        discovery_url = issuer.rstrip('/') + '/.well-known/openid-configuration'
        oidc_cfg = requests.get(discovery_url, timeout=10).json()
        jwks_uri = oidc_cfg['jwks_uri']
        jwks_data = requests.get(jwks_uri, timeout=10).json()
        keys = JsonWebKey.import_key_set(jwks_data)
        _jwks_cache.update({"issuer": issuer, "keys": keys, "fetched_at": now})
        return keys


def _verify_jwt(token: str, config) -> dict:
    """Validate ``token`` against the configured OIDC issuer.

    Returns the decoded claims on success. Raises ``_NotAJWT`` for non-
    JWT-shaped input. Raises ``authlib.jose.JoseError`` for any other
    validation failure (bad sig, expired, wrong iss/aud, missing scope).
    """
    from authlib.jose import JsonWebToken
    from authlib.jose.errors import JoseError

    if not _looks_like_jwt(token):
        raise _NotAJWT()

    issuer = config.OIDCIssuer.rstrip('/')
    keys = _fetch_jwks(issuer)

    claims_options = {
        "iss": {"essential": True, "value": issuer},
    }
    if config.OIDCAudience:
        claims_options["aud"] = {"essential": True, "value": config.OIDCAudience}

    jwt = JsonWebToken(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'])
    claims = jwt.decode(token, key=keys, claims_options=claims_options)
    claims.validate()  # exp / nbf / iat / iss / aud

    if config.OIDCRequiredScope:
        scope_claim = claims.get('scope') or ''
        scopes = scope_claim.split() if isinstance(scope_claim, str) else list(scope_claim)
        if config.OIDCRequiredScope not in scopes:
            raise JoseError(f"missing required scope '{config.OIDCRequiredScope}'")

    return claims


def _resolve_systemuser_from_claims(claims: dict, config) -> Optional[str]:
    """Map OIDC claims to an existing systemUser.name. Returns None when no
    match exists. Auto-provisioning is intentionally out of scope for v1
    so admins keep explicit control over who has API access."""
    from .persistency import dbController

    claim_name = config.OIDCUsernameClaim or 'preferred_username'
    username = (
        claims.get(claim_name)
        or claims.get('email')
        or claims.get('sub')
    )
    if not username:
        return None

    try:
        users = dbController.query_systemUser(query=f'name = "{username}"')
    except Exception as e:
        logger.error("systemUser lookup failed for OIDC user %s: %s", username, e)
        return None

    if not users:
        logger.warning(
            "OIDC user %r authenticated successfully but has no matching "
            "systemUser; create the user or set FTS_OIDC_USERNAME_CLAIM to "
            "a claim that matches",
            username,
        )
        return None

    user = users[0]
    try:
        dbController.create_APICall(
            user_id=user.uid,
            timestamp=dt.datetime.now(),
            content=request.data,
            endpoint=request.base_url,
        )
    except Exception as e:
        logger.debug("API call audit log skipped: %s", e)
    return user.name


@auth.verify_token
def verify_token(token):
    from .persistency import dbController

    if not token:
        return None

    config = MainConfig.instance()
    issuer = getattr(config, 'OIDCIssuer', '') or ''

    if issuer:
        try:
            claims = _verify_jwt(token, config)
        except _NotAJWT:
            # Not JWT-shaped; let the legacy lookup handle it below.
            pass
        except Exception as e:
            # JWT-shaped but failed validation. Refuse outright -- do
            # not fall back to legacy DB lookup, otherwise an attacker
            # who crafts a malformed JWT could probe whether a token
            # string happens to also exist in APIUser/systemUser.
            logger.warning("OIDC JWT validation failed: %s", e)
            return None
        else:
            return _resolve_systemuser_from_claims(claims, config)

    # Legacy static-token path. Behaviour unchanged from upstream.
    if token:
        output = dbController.query_APIUser(query=f'token = "{token}"')
        if output:
            return output[0].Username
        else:
            output = dbController.query_systemUser(query=f'token = "{token}"')
            if output:
                output = output[0]
                dbController.create_APICall(
                    user_id=output.uid,
                    timestamp=dt.datetime.now(),
                    content=request.data,
                    endpoint=request.base_url,
                )
                return output.name
    return None