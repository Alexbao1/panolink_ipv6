from dataclasses import dataclass

from diamond_miner.defaults import UNIVERSE_SUBSET
from diamond_miner.queries.query import Query, links_table,map_table
from diamond_miner.typing import IPNetwork


@dataclass(frozen=True)
class InsertMap(Query):
    """
    Insert measurement results from a CSV file.
    """

    def statement(
        self, measurement_id: str, subset: IPNetwork = UNIVERSE_SUBSET
    ) -> str:
        return f"""
        INSERT INTO {map_table(measurement_id)}
        WITH link_counts AS
        (
            SELECT near_asn, far_asn, COUNT(*) AS count
            FROM {links_table(measurement_id)}
            WHERE near_asn != far_asn AND near_asn != '' AND far_asn != ''
            GROUP BY near_asn, far_asn
        ),
        total_counts AS (
            SELECT near_asn, SUM(count) AS total_count
            FROM link_counts
            GROUP BY near_asn 
        )
        SELECT link_counts.near_asn , link_counts.far_asn, link_counts.count / total_counts.total_count AS rate
        FROM link_counts
        INNER JOIN total_counts ON link_counts.near_asn = total_counts.near_asn;
        """