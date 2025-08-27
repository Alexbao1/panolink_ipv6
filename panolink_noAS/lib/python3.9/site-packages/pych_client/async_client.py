import builtins
from types import TracebackType
from typing import Any, AsyncIterator, List, Optional, Type

import httpx

from pych_client.base import get_credentials, get_http_params
from pych_client.constants import DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_WRITE_TIMEOUT
from pych_client.exceptions import ClickHouseException
from pych_client.typing import Data, Params, Settings

try:
    import orjson as json
except ModuleNotFoundError:
    import json  # type: ignore


class AsyncClickHouseClient:
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
        self.client = httpx.AsyncClient(
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

    async def __aenter__(self) -> "AsyncClickHouseClient":
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self.client.aclose()

    async def execute(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> httpx.Response:
        r = await self.client.post(
            "/",
            content=data,  # type: ignore
            params=get_http_params(query, params, settings),
        )
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise ClickHouseException(query, r.text) from e
        return r

    async def stream(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> Any:
        return self.client.stream(
            "POST", "/", content=data, params=get_http_params(query, params, settings)
        )

    async def bytes(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> builtins.bytes:
        r = await self.execute(query, params, data, settings)
        return r.content

    async def iter_bytes(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> AsyncIterator[builtins.bytes]:
        stream = await self.stream(query, params, data, settings)
        async with stream as r:
            async for chunk in r.aiter_bytes():
                yield chunk

    async def text(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> str:
        r = await self.execute(query, params, data, settings)
        return r.text.strip()

    async def iter_text(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> AsyncIterator[str]:
        stream = await self.stream(query, params, data, settings)
        async with stream as r:
            async for line in r.aiter_lines():
                yield line

    async def json(
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
        result = await self.text(query, params, data, settings)
        return [json.loads(line) for line in result.split("\n") if line]
        # except JSONDecodeError as e:
        #     # TODO: How to handle exception formatting in this case?
        #     raise ClickHouseException(result) from e

    async def iter_json(
        self,
        query: str,
        params: Params = None,
        data: Data = None,
        settings: Settings = None,
    ) -> AsyncIterator[dict]:
        settings = settings or {}
        settings = {
            **settings,
            "default_format": "JSONEachRow",
            "output_format_json_quote_64bit_integers": 0,
        }
        async for line in self.iter_text(query, params, data, settings):
            if line:
                yield json.loads(line)
