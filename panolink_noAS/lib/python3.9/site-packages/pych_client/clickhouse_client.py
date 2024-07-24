from pych_client.typing import Params, Settings


def get_clickhouse_client_args(
    config: dict, query: str, params: Params = None, settings: Settings = None
) -> list[str]:
    """Return the equivalent arguments for the `clickhouse-client` command."""
    args = [
        f"--query={query}",
        f"--database={config['database']}",
        f"--user={config['username']}",
    ]
    if config["password"]:
        args.append(f"--password={config['password']}")
    if params:
        args.extend(f"--param_{k}={v}" for k, v in params.items())
    if settings:
        if f := settings.pop("default_format", None):
            settings["format"] = f
        args.extend(f"--{k}={v}" for k, v in settings.items())
    return args
