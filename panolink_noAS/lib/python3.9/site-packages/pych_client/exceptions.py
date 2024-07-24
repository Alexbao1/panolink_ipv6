class ClickHouseException(Exception):
    def __init__(self, query: str, err: str):
        err = "\n".join(err.split(". "))
        msg = f"Query\n{query}\n\nError\n{err}"
        super().__init__(msg)
