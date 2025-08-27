from dataclasses import dataclass

from diamond_miner.defaults import UNIVERSE_SUBSET
from diamond_miner.queries.fragments import date_time
from diamond_miner.queries.query import Query, StoragePolicy, bgp_table
from diamond_miner.typing import IPNetwork


@dataclass(frozen=True)
class CreateBGPTable(Query):
    SORTING_KEY = "ipv6_range"

    storage_policy: StoragePolicy = StoragePolicy()

    def statement(
        self, measurement_id: str, subset: IPNetwork = UNIVERSE_SUBSET
    ) -> str:
        return f"""
        CREATE TABLE IF NOT EXISTS {bgp_table(measurement_id)}
        (
            prefix                IPv4,
            len                   UInt8,
            ip_asn                String,
            ipv6_range            Tuple(IPv6, IPv6) DEFAULT IPv6CIDRToRange(IPv4ToIPv6(prefix), CAST((len + 96) AS UInt8)),
            PRIMARY KEY (ipv6_range)
        )
        ENGINE MergeTree
        ORDER BY ({self.SORTING_KEY})
        TTL {date_time(self.storage_policy.archive_on)} TO VOLUME '{self.storage_policy.archive_to}'
        SETTINGS storage_policy = '{self.storage_policy.name}'
        """
