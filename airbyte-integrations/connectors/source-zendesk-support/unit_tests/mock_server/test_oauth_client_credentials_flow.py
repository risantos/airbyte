# Copyright (c) 2026 Airbyte, Inc., all rights reserved.

"""
Tests for the OAuth2.0 client credentials authentication flow.

Zendesk's client credentials grant returns no refresh token, so there is nothing to persist
and nothing to rotate: the connector POSTs the same request whenever it needs a token. These
tests pin the shape of that request, because Zendesk accepts a malformed `scope` and issues a
token for it, then rejects every API call with 403 — a mistake that would otherwise surface as
a broken sync rather than a failed token request.

Note: the CDK's OAuthAuthenticator sends token requests as form-urlencoded data, but
HttpMocker's matcher tries to parse bodies as JSON. As in `test_oauth_refresh_flow.py`, the
token endpoint is registered directly on the underlying requests_mock.Mocker to bypass the
JSON-only body matcher; that also gives direct access to the recorded request bodies.
"""

import json
from datetime import timedelta
from unittest import TestCase
from unittest.mock import patch
from urllib.parse import parse_qs

import freezegun

from airbyte_cdk.models import SyncMode
from airbyte_cdk.test.mock_http import HttpMocker, HttpResponse
from airbyte_cdk.utils.datetime_helpers import ab_datetime_now

from .config import ConfigBuilder
from .request_builder import OAuthBearerAuthenticator, ZendeskSupportRequestBuilder
from .response_builder import TagsRecordBuilder, TagsResponseBuilder
from .utils import read_stream


_NOW = ab_datetime_now()
_START_DATE = _NOW.subtract(timedelta(weeks=104))
_SUBDOMAIN = "d3v-airbyte"
_OAUTH_TOKEN_URL = f"https://{_SUBDOMAIN}.zendesk.com/oauth/tokens"

_CLIENT_ID = "test_client_id"
_CLIENT_SECRET = "test_client_secret"
_ACCESS_TOKEN = "client_credentials_access_token"
_SECOND_ACCESS_TOKEN = "client_credentials_access_token_2"

# The manifest's fallbacks when the user leaves `scope` and `expires_in` unset.
_DEFAULT_SCOPE = "read"
_DEFAULT_EXPIRES_IN = "172800"


def _build_config(scope: str = None, expires_in: int = None) -> dict:
    return (
        ConfigBuilder()
        .with_subdomain(_SUBDOMAIN)
        .with_start_date(_START_DATE)
        .with_oauth_client_credentials(
            client_id=_CLIENT_ID,
            client_secret=_CLIENT_SECRET,
            scope=scope,
            expires_in=expires_in,
        )
        .build()
    )


def _token_response(access_token: str, scope: str = _DEFAULT_SCOPE, expires_in: int = 172800) -> str:
    """The response Zendesk documents for this grant: no refresh token."""
    return json.dumps(
        {
            "access_token": access_token,
            "token_type": "bearer",
            "scope": scope,
            "expires_in": expires_in,
        }
    )


def _submitted_token_request(matcher, index: int = 0) -> dict:
    """Return one recorded token request body as a flat dict of single values."""
    return {key: values[0] for key, values in parse_qs(matcher.request_history[index].text).items()}


@freezegun.freeze_time(_NOW.isoformat())
class TestClientCredentialsTokenRequest(TestCase):
    """The connector asks Zendesk for a token with the parameters Zendesk documents."""

    @HttpMocker()
    def test_given_client_credentials_when_read_then_requests_token_and_syncs(self, http_mocker):
        config = _build_config()

        token_matcher = http_mocker._mocker.post(_OAUTH_TOKEN_URL, text=_token_response(_ACCESS_TOKEN), status_code=200)
        http_mocker.get(
            ZendeskSupportRequestBuilder.tags_endpoint(OAuthBearerAuthenticator(_ACCESS_TOKEN)).with_page_size(100).build(),
            TagsResponseBuilder.tags_response().with_record(TagsRecordBuilder.tags_record()).build(),
        )

        output = read_stream("tags", SyncMode.full_refresh, config)

        assert token_matcher.call_count == 1
        assert len(output.records) == 1

    @HttpMocker()
    def test_given_no_scope_or_lifetime_when_read_then_submits_manifest_defaults(self, http_mocker):
        """A config that sets neither field still sends `scope` and `expires_in`.

        Omitting `scope` makes Zendesk grant full read and write access, and omitting
        `expires_in` gives a 30-minute token on clients created on or after 2026-04-30 — short
        enough to expire inside a sync. Both fallbacks live in the manifest, not in the spec
        `default`, because a hand-written config file never has the spec defaults applied.
        """
        config = _build_config()

        token_matcher = http_mocker._mocker.post(_OAUTH_TOKEN_URL, text=_token_response(_ACCESS_TOKEN), status_code=200)
        http_mocker.get(
            ZendeskSupportRequestBuilder.tags_endpoint(OAuthBearerAuthenticator(_ACCESS_TOKEN)).with_page_size(100).build(),
            TagsResponseBuilder.tags_response().with_record(TagsRecordBuilder.tags_record()).build(),
        )

        read_stream("tags", SyncMode.full_refresh, config)

        submitted = _submitted_token_request(token_matcher)
        assert submitted["grant_type"] == "client_credentials"
        assert submitted["client_id"] == _CLIENT_ID
        assert submitted["client_secret"] == _CLIENT_SECRET
        assert submitted["scope"] == _DEFAULT_SCOPE
        assert submitted["expires_in"] == _DEFAULT_EXPIRES_IN

    @HttpMocker()
    def test_given_token_request_when_read_then_sends_no_refresh_token_and_no_plural_scopes(self, http_mocker):
        """Two keys Zendesk must not receive.

        The CDK adds `refresh_token` to every token request body regardless of grant type; it
        is `None` here and `requests` drops it while form-encoding. And the singular `scope`
        must not be accompanied by the plural `scopes`, which is what the OAuthAuthenticator
        `scopes` field would emit (as a JSON list). Zendesk's own reference warns the two
        parameters are different, and answers the plural one with a token that then 403s.
        """
        config = _build_config()

        token_matcher = http_mocker._mocker.post(_OAUTH_TOKEN_URL, text=_token_response(_ACCESS_TOKEN), status_code=200)
        http_mocker.get(
            ZendeskSupportRequestBuilder.tags_endpoint(OAuthBearerAuthenticator(_ACCESS_TOKEN)).with_page_size(100).build(),
            TagsResponseBuilder.tags_response().with_record(TagsRecordBuilder.tags_record()).build(),
        )

        read_stream("tags", SyncMode.full_refresh, config)

        body = token_matcher.request_history[0].text
        submitted = _submitted_token_request(token_matcher)
        assert "refresh_token" not in submitted, body
        assert "scopes" not in submitted, body

    @HttpMocker()
    def test_given_custom_scope_and_lifetime_when_read_then_submits_them(self, http_mocker):
        config = _build_config(scope="tickets:read users:read", expires_in=3600)

        token_matcher = http_mocker._mocker.post(
            _OAUTH_TOKEN_URL,
            text=_token_response(_ACCESS_TOKEN, scope="tickets:read users:read", expires_in=3600),
            status_code=200,
        )
        http_mocker.get(
            ZendeskSupportRequestBuilder.tags_endpoint(OAuthBearerAuthenticator(_ACCESS_TOKEN)).with_page_size(100).build(),
            TagsResponseBuilder.tags_response().with_record(TagsRecordBuilder.tags_record()).build(),
        )

        read_stream("tags", SyncMode.full_refresh, config)

        submitted = _submitted_token_request(token_matcher)
        assert submitted["scope"] == "tickets:read users:read"
        assert submitted["expires_in"] == "3600"

    @HttpMocker()
    def test_given_blank_scope_when_read_then_falls_back_to_the_default_scope(self, http_mocker):
        """A cleared `scope` is an empty string, not a missing key.

        Sending it on would make Zendesk grant full read and write access, so the manifest
        reads the field with `or` rather than a two-argument `get`. `expires_in` carries the
        same guard, but spec validation rejects an empty string for an `integer` field before
        the manifest sees it, so only `scope` can actually arrive blank.
        """
        config = _build_config(scope="")

        token_matcher = http_mocker._mocker.post(_OAUTH_TOKEN_URL, text=_token_response(_ACCESS_TOKEN), status_code=200)
        http_mocker.get(
            ZendeskSupportRequestBuilder.tags_endpoint(OAuthBearerAuthenticator(_ACCESS_TOKEN)).with_page_size(100).build(),
            TagsResponseBuilder.tags_response().with_record(TagsRecordBuilder.tags_record()).build(),
        )

        read_stream("tags", SyncMode.full_refresh, config)

        submitted = _submitted_token_request(token_matcher)
        assert submitted["scope"] == _DEFAULT_SCOPE


@freezegun.freeze_time(_NOW.isoformat())
class TestClientCredentialsTokenRejected(TestCase):
    """`REFRESH_TOKEN_THEN_RETRY` works for a grant that has no refresh token.

    Zendesk's guidance for this grant is to repeat the original token request, which is
    exactly what the CDK's refresh does here. The existing `invalid_token` response filter
    therefore needs no change, but nothing else proves it applies to this authenticator.
    """

    @HttpMocker()
    def test_given_401_invalid_token_when_read_then_requests_new_token_and_retries(self, http_mocker):
        config = _build_config()

        http_mocker.get(
            ZendeskSupportRequestBuilder.tags_endpoint(OAuthBearerAuthenticator(_ACCESS_TOKEN)).with_page_size(100).build(),
            HttpResponse(
                json.dumps(
                    {
                        "error": "invalid_token",
                        "error_description": "The access token provided is expired, revoked, malformed or invalid for other reasons.",
                    }
                ),
                401,
            ),
        )
        http_mocker.get(
            ZendeskSupportRequestBuilder.tags_endpoint(OAuthBearerAuthenticator(_SECOND_ACCESS_TOKEN)).with_page_size(100).build(),
            TagsResponseBuilder.tags_response().with_record(TagsRecordBuilder.tags_record()).build(),
        )
        token_matcher = http_mocker._mocker.post(
            _OAUTH_TOKEN_URL,
            [
                {"text": _token_response(_ACCESS_TOKEN), "status_code": 200},
                {"text": _token_response(_SECOND_ACCESS_TOKEN), "status_code": 200},
            ],
        )

        with patch("time.sleep", return_value=None):
            output = read_stream("tags", SyncMode.full_refresh, config)

        # One token for the first request, a second after Zendesk rejected it.
        assert token_matcher.call_count == 2
        assert _submitted_token_request(token_matcher, 1)["grant_type"] == "client_credentials"
        assert len(output.records) == 1
        assert len(output.errors) == 0
