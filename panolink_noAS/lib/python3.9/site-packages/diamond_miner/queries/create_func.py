from dataclasses import dataclass

from diamond_miner.defaults import UNIVERSE_SUBSET
from diamond_miner.queries.query import Query
from diamond_miner.typing import IPNetwork

@dataclass(frozen=True)
class CreateFunc(Query):
    def statement(
        self, measurement_id: str, subset: IPNetwork = UNIVERSE_SUBSET
    ) -> str:
        return f"""
            CREATE FUNCTION random_asn AS () ->if(RAND() % 2, 'AS1', 'AS2');
        """


