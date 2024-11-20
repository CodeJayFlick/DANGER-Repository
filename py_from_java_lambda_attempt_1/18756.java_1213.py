Here is the translation of the Java code into Python:

```Python
import json
from typing import Optional

class AwsAuthenticationProvider:
    AUTH_TYPE_VALUE = "AWS"

    @staticmethod
    def create(region: str) -> 'HttpAuthentication':
        return AwsAuthenticationProvider.create(region, None)

    @staticmethod
    def create(region: str, profile: str) -> 'HttpAuthentication':
        return HttpAuthentication(AwsRegion(region), profile)

    def get_auth_type_value(self) -> str:
        return self.AUTH_TYPE_VALUE

    def build(self, parameters: dict) -> 'HttpAuthentication':
        region_name = parameters.get(NessieConfigConstants.CONF_NESSIE_AWS_REGION)
        if not region_name:
            region_name = "US_WEST_2"

        region = AwsRegion(region_name)

        profile = parameters.get(NessieConfigConstants.CONF_NESSIE_AWS_PROFILE)

        return self.create(region, profile)


class HttpAuthentication:
    def __init__(self, region: 'AwsRegion', profile: str):
        self.region = region
        if profile is not None:
            self.aws_credentials_provider = DefaultCredentialsProvider(profile)
        else:
            self.aws_credentials_provider = DefaultCredentialsProvider()

    def apply_to_http_client(self, client) -> None:
        client.register(AwsHttpAuthenticationFilter(self.region, self.aws_credentials_provider))


class AwsRegion:
    REGIONS = ["US_WEST_2", "EU_CENTRAL_1"]

    @staticmethod
    def from_name(region: str):
        if region in AwsRegion.REGIONS:
            return region
        else:
            raise ValueError(f"Unknown region '{region}'")


class DefaultCredentialsProvider:
    def __init__(self, profile=None):
        self.profile = profile

    def build(self) -> 'AwsCredentialsProvider':
        pass


class AwsHttpAuthenticationFilter:
    def __init__(self, region: str, aws_credentials_provider: 'AwsCredentialsProvider'):
        self.region = region
        self.aws_credentials_provider = aws_credentials_provider
        self.object_mapper = json.JSONEncoder()
        self.signer = Aws4Signer()

    def prepare_request(self, uri: str, method: str, entity: Optional[dict]) -> dict:
        request = {"uri": uri, "method": method}
        if entity is not None:
            try:
                bytes_data = json.dumps(entity).encode("utf-8")
                request["content_stream_provider"] = lambda: io.BytesIO(bytes_data)
            except Exception as e:
                raise RuntimeError(str(e))
        return request

    def filter(self, context) -> None:
        modified_request = self.signer.sign(
            self.prepare_request(context.get_uri(), context.get_method(), context.get_body()),
            {"signing_name": "execute-api", "aws_credentials": self.aws_credentials_provider.resolve_credentials(),
             "signing_region": self.region}
        )
        for header, values in modified_request.items():
            if context.get_headers().get(header):
                continue
            for value in values:
                context.put_header(header, value)
```

Please note that this is a direct translation of the Java code into Python. The resulting Python code may not be optimal or idiomatic Python due to the complexity and nuances of translating Java code directly into Python.