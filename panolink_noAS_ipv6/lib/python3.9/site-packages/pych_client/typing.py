from typing import AsyncIterable, Iterable, Optional, Union

Data = Union[str, bytes, AsyncIterable[bytes], Iterable[bytes], None]
Params = Optional[dict]
Settings = Optional[dict]
