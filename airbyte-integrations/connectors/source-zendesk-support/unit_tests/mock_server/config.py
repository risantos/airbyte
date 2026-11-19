# Copyright (c) 2023 Airbyte, Inc., all rights reserved.

from typing import Any, Dict, Optional

from airbyte_cdk.utils.datetime_helpers import AirbyteDateTime


class ConfigBuilder:
    def __init__(self) -> None:
        self._subdomain: Optional[str] = None
        self._start_date: Optional[str] = None
        self._credentials: Dict[str, Any] = {}
        self._ignore_pagination: Optional[bool] = None

    def with_subdomain(self, subdomain: str) -> "ConfigBuilder":
        self._subdomain = subdomain
        return self

    def with_oauth_credentials(self, access_token: str) -> "ConfigBuilder":
        self._credentials["access_token"] = access_token
        self._credentials["credentials"] = "oauth2.0"
        return self

    def with_basic_auth_credentials(self, email: str, password: str) -> "ConfigBuilder":
        self._credentials["api_token"] = password
        self._credentials["credentials"] = "api_token"
        self._credentials["email"] = email
        return self

    def with_oauth_refresh_credentials(
        self,
        client_id: str,
        client_secret: str,
        refresh_token: str,
        access_token: str,
        token_expiry_date: str,
    ) -> "ConfigBuilder":
        self._credentials["credentials"] = "oauth2_refresh"
        self._credentials["client_id"] = client_id
        self._credentials["client_secret"] = client_secret
        self._credentials["refresh_token"] = refresh_token
        self._credentials["access_token"] = access_token
        self._credentials["token_expiry_date"] = token_expiry_date
        return self

    def with_oauth_client_credentials(
        self,
        client_id: str,
        client_secret: str,
        scope: Optional[str] = None,
        expires_in: Optional[int] = None,
    ) -> "ConfigBuilder":
        """Build `oauth2_client_credentials` credentials.

        `scope` and `expires_in` are left out when not given, so a test can cover the
        manifest defaults (`read` and 172800) as a user who never touched either field sees
        them. There is no access token or refresh token: this grant returns no refresh token
        and the connector requests a fresh access token on every sync.
        """
        self._credentials["credentials"] = "oauth2_client_credentials"
        self._credentials["client_id"] = client_id
        self._credentials["client_secret"] = client_secret
        if scope is not None:
            self._credentials["scope"] = scope
        if expires_in is not None:
            self._credentials["expires_in"] = expires_in
        return self

    def with_start_date(self, start_date: AirbyteDateTime) -> "ConfigBuilder":
        self._start_date = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        return self

    def with_ignore_pagination(self) -> "ConfigBuilder":
        self._ignore_pagination = True
        return self

    def build(self) -> Dict[str, Any]:
        config = {}
        if self._subdomain:
            config["subdomain"] = self._subdomain
        if self._start_date:
            config["start_date"] = self._start_date
        if self._credentials:
            config["credentials"] = self._credentials
        if self._ignore_pagination:
            config["ignore_pagination"] = self._ignore_pagination
        return config
