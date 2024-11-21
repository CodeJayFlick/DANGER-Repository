from typing import Any

class ProvidedDynamoClientConfig:
    def __init__(self, dynamo_db_client: Any):
        self._dynamo_db_client = dynamo_db_client

    @classmethod
    def from_dynamo_db_client(cls, db: Any) -> 'ProvidedDynamoClientConfig':
        return cls(db)

    @property
    def dynamo_db_client(self) -> Any:
        return self._dynamo_db_client

    def with_dynamo_db_client(self, dynamo_db_client: Any) -> 'ProvidedDynamoClientConfig':
        return ProvidedDynamoClientConfig(dynamo_db_client)
