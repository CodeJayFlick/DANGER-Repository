from typing import Optional

class DefaultDynamoClientConfig:
    def __init__(self):
        self._endpoint_uri: str = None
        self._region: str = None
        self._credentials_provider: Optional['AwsCredentialsProvider'] = None
        self._dynamodb_client: Optional['DynamoDbClient'] = None

    @property
    def endpoint_uri(self) -> Optional[str]:
        return self._endpoint_uri

    @endpoint_uri.setter
    def endpoint_uri(self, value: str):
        self._endpoint_uri = value

    def with_endpoint_uri(self, endpoint_uri: str) -> 'DefaultDynamoClientConfig':
        self.endpoint_uri = endpoint_uri
        return self

    @property
    def region(self) -> Optional[str]:
        return self._region

    @region.setter
    def region(self, value: str):
        self._region = value

    def with_region(self, region: str) -> 'DefaultDynamoClientConfig':
        self.region = region
        return self

    @property
    def credentials_provider(self) -> Optional['AwsCredentialsProvider']:
        return self._credentials_provider

    @credentials_provider.setter
    def credentials_provider(self, value: 'AwsCredentialsProvider'):
        self._credentials_provider = value

    def with_credentials_provider(self, credentials_provider: 'AwsCredentialsProvider') -> 'DefaultDynamoClientConfig':
        self.credentials_provider = credentials_provider
        return self

    @property
    def dynamodb_client(self) -> Optional['DynamoDbClient']:
        return self._dynamodb_client

    @dynamodb_client.setter
    def dynamodb_client(self, value: 'DynamoDbClient'):
        self._dynamodb_client = value

    def with_dynamodb_client(self, dynamodb_client: 'DynamoDbClient') -> 'DefaultDynamoClientConfig':
        self.dynamodb_client = dynamodb_client
        return self
