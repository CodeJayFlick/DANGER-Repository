import urllib.parse

class HdfsRepositoryFactory:
    def __init__(self):
        self.config = None

    def create_instance(self, config=None):
        if not config:
            config = {}
        self.config = config

    def get_repository(self, name: str, uri: str) -> 'HdfsRepository':
        parsed_uri = urllib.parse.urlparse(uri)
        scheme = parsed_uri.scheme
        if scheme.lower() != "hdfs":
            raise ValueError(f"Invalid HDFS URL: {uri}")
        return HdfsRepository(name, parsed_uri, self.config)

    def get_supported_schemes(self) -> set:
        return {"hdfs"}

class HdfsRepository:
    def __init__(self, name: str, uri: urllib.parse.ParseResult, config):
        self.name = name
        self.uri = uri
        self.config = config

# Example usage:
factory = HdfsRepositoryFactory()
repository = factory.get_repository("my-repo", "hdfs://example.com/path/to/data")
print(repository.name)  # Output: my-repo
