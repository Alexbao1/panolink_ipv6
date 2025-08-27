from dataclasses import dataclass

from diamond_miner.defaults import UNIVERSE_SUBSET
from diamond_miner.queries.fragments import date_time
from diamond_miner.queries.query import Query, StoragePolicy, map_table
from diamond_miner.typing import IPNetwork


@dataclass(frozen=True)
class CreateMapTable(Query):
    """Create the table containing the cumulative number of probes sent over the rounds."""

    SORTING_KEY = "src_asn, dst_asn"

    storage_policy: StoragePolicy = StoragePolicy()

    def statement(
        self, measurement_id: str, subset: IPNetwork = UNIVERSE_SUBSET
    ) -> str:
        return f"""
        CREATE TABLE IF NOT EXISTS {map_table(measurement_id)}
        (
            src_asn                String,
            dst_asn                String,
            rate                   Float64,
            PRIMARY KEY (src_asn, dst_asn)
        )
        ENGINE MergeTree
        ORDER BY ({self.SORTING_KEY})
        TTL {date_time(self.storage_policy.archive_on)} TO VOLUME '{self.storage_policy.archive_to}'
        SETTINGS storage_policy = '{self.storage_policy.name}'
        """
