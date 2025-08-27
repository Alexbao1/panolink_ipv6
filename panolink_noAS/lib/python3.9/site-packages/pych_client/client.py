import builtins
from types import TracebackType
from typing import Any, Iterator, List, Optional, Type

import httpx

from pych_client.base import get_credentials, get_http_params
from pych_client.constants import DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_WRITE_TIMEOUT
from pych_client.exceptions import ClickHouseException
from pych_client.typing import Data, Params, Settings

try:
    import orjson as json
except ModuleNotFoundError:
    import json  # type: ignore


class ClickHouseClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        database: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        *,
        connect_timeout: Optional[float] = DEFAULT_CONNECT_TIMEOUT,
        read_write_timeout: Optional[float] = DEFAULT_READ_WRITE_TIMEOUT,
    ):
        base_url, database, username, password = get_credentials(
            base_url, database, username, password
        )
        self.client = httpx.Client(
            base_url=base_url,
            headers={"Accept-encoding": "gzip"},
            params={"database": database, "user": username, "password": password},
            timeout=httpx.Timeout(
                connect_timeout, read=read_write_timeout, write=read_write_timeout
            ),
        )
        self.config = {
            "base_url": base_url,
            "database": database,
            "username": username,
            "password": password,
            "connect_timeout": connect_timeout,
            "read_write_timeout": read_write_timeout,
        }

    def __enter__(self) -> "ClickHouseClient":
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.client.close()

    def execute(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> httpx.Response:
        r = self.client.post(
            "/",
            content=data,  # type: ignore
            params=get_http_params(query, params, settings),
        )
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise ClickHouseException(query, r.text) from e
        return r

    def stream(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> Any:
        return self.client.stream(
            "POST",
            "/",
            content=data,  # type: ignore
            params=get_http_params(query, params, settings),
        )

    def bytes(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> builtins.bytes:
        return self.execute(query, params, data, settings).content

    def iter_bytes(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> Iterator[builtins.bytes]:
        with self.stream(query, params, data, settings) as r:
            yield from r.iter_bytes()

    def text(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> str:
        return self.execute(query, params, data, settings).text.strip()

    def iter_text(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> Iterator[str]:
        with self.stream(query, params, data, settings) as r:
            yield from r.iter_lines()

    def json(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> List[dict]:
        settings = settings or {}
        settings = {
            **settings,
            "default_format": "JSONEachRow",
            "output_format_json_quote_64bit_integers": 0,
        }
        result = self.text(query, params, data, settings)
        return [json.loads(line) for line in result.split("\n") if line]
        # except JSONDecodeError as e:
        #     # TODO: How to handle exception formatting in this case?
        #     raise ClickHouseException(result) from e

    def iter_json(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> Iterator[dict]:
        settings = settings or {}
        settings = {
            **settings,
            "default_format": "JSONEachRow",
            "output_format_json_quote_64bit_integers": 0,
        }
        for line in self.iter_text(query, params, data, settings):
            if line:
                yield json.loads(line)
