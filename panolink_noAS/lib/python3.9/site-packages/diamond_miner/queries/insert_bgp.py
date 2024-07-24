from dataclasses import dataclass

from diamond_miner.defaults import UNIVERSE_SUBSET
from diamond_miner.queries.query import Query, bgp_table
from diamond_miner.typing import IPNetwork


@dataclass(frozen=True)
class InsertBGP(Query):
    """
    Insert measurement results from a CSV file.
    """

    def statement(
        self, measurement_id: str, subset: IPNetwork = UNIVERSE_SUBSET
    ) -> str:
        return f"INSERT INTO {bgp_table(measurement_id)} FORMAT TSVWithNames"