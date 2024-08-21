from dataclasses import dataclass

from diamond_miner.defaults import (
    DEFAULT_PREFIX_LEN_V4,
    DEFAULT_PREFIX_LEN_V6,
    UNIVERSE_SUBSET,
)
from diamond_miner.queries.fragments import cut_ipv6, date_time
from diamond_miner.queries.query import Query, StoragePolicy, links_table, results_view, group_mapping, links_view
from diamond_miner.typing import IPNetwork


@dataclass(frozen=True)
class CreateLinksView(Query):
    """Create the table used to store the measurement results from the prober."""

    prefix_len_v4: int = DEFAULT_PREFIX_LEN_V4
    prefix_len_v6: int = DEFAULT_PREFIX_LEN_V6
    storage_policy: StoragePolicy = StoragePolicy()

    def statement(
        self, measurement_id: str, subset: IPNetwork = UNIVERSE_SUBSET
    ) -> str:
        return f"""
        CREATE MATERIALIZED VIEW IF NOT EXISTS {links_view(measurement_id)}
        ENGINE = MergeTree() ORDER BY group_id POPULATE AS
        SELECT * from(
            SELECT probe_protocol, probe_src_addr, near_addr,far_addr,probe_dst_addr,near_ttl,ip_asn,asn
            FROM {links_table(measurement_id)} as link
            INNER JOIN {results_view(measurement_id)} as results ON 
            link.probe_dst_addr == results.probe_dst_addr AND 
            link.near_ttl == results.probe_ttl
            ) as tmp
            INNER JOIN {group_mapping(measurement_id)} gm USING ip_asn,asn
        """