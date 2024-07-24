import atexit
import readline
from argparse import ArgumentParser
from contextlib import suppress
from pathlib import Path
from typing import Optional, Sequence

from pych_client import ClickHouseClient
from pych_client.exceptions import ClickHouseException

HISTFILE = Path.home() / ".pych-client-history"


def main(args_: Optional[Sequence[str]] = None) -> None:
    parser = ArgumentParser()
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--database", default=None)
    parser.add_argument("--username", default=None)
    parser.add_argument("--password", default=None)
    args = parser.parse_args(args_)

    with suppress(FileNotFoundError):
        readline.read_history_file(HISTFILE)

    readline.parse_and_bind("tab: complete")
    atexit.register(readline.write_history_file, HISTFILE)

    with ClickHouseClient(
        base_url=args.base_url,
        database=args.database,
        username=args.username,
        password=args.password,
    ) as client:
        hostname = client.text("SELECT hostname()")
        while True:
            try:
                inp = input(f"{hostname} :) ").strip()
                if inp:
                    out = client.text(inp, settings={"default_format": "PrettyCompact"})
                    print(out)
            except ClickHouseException as e:
                print(f"\033[91m{e}\033[0m")
            except (EOFError, KeyboardInterrupt):
                break
