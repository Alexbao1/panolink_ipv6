import json
import os
from typing import Optional, Tuple

from pych_client.constants import (
    BASE_URL_ENV,
    CREDENTIALS_FILE,
    DATABASE_ENV,
    DEFAULT_BASE_URL,
    DEFAULT_DATABASE,
    DEFAULT_PASSWORD,
    DEFAULT_USERNAME,
    PASSWORD_ENV,
    USERNAME_ENV,
)
from pych_client.logger import logger
from pych_client.typing import Params, Settings

# TODO: Benchmark different functions


def get_credentials(
    base_url: Optional[str],
    database: Optional[str],
    username: Optional[str],
    password: Optional[str],
) -> Tuple[str, str, str, str]:
    if base_url or database or username or password:
        logger.debug("using credentials from arguments")
        return (
            base_url or DEFAULT_BASE_URL,
            database or DEFAULT_DATABASE,
            username or DEFAULT_USERNAME,
            password or DEFAULT_PASSWORD,
        )
    if (
        BASE_URL_ENV in os.environ
        or DATABASE_ENV in os.environ
        or USERNAME_ENV in os.environ
        or PASSWORD_ENV in os.environ
    ):
        logger.debug("using credentials from environment")
        return (
            os.environ.get(BASE_URL_ENV, DEFAULT_BASE_URL),
            os.environ.get(DATABASE_ENV, DEFAULT_DATABASE),
            os.environ.get(USERNAME_ENV, DEFAULT_USERNAME),
            os.environ.get(PASSWORD_ENV, DEFAULT_PASSWORD),
        )
    if CREDENTIALS_FILE.exists():
        logger.debug("using credentials from %s", CREDENTIALS_FILE)
        credentials = json.loads(CREDENTIALS_FILE.read_text())
        return (
            credentials.get("base_url", DEFAULT_BASE_URL),
            credentials.get("database", DEFAULT_DATABASE),
            credentials.get("username", DEFAULT_USERNAME),
            credentials.get("password", DEFAULT_PASSWORD),
        )
    return DEFAULT_BASE_URL, DEFAULT_DATABASE, DEFAULT_USERNAME, DEFAULT_PASSWORD


def get_http_params(query: str, params: Params, settings: Settings) -> dict:
    http_params = {"query": query}
    if params:
        query_params = {f"param_{k}": v for k, v in params.items()}
        http_params = {**http_params, **query_params}
    if settings:
        http_params = {**http_params, **settings}
    return http_params
