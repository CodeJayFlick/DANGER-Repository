import boto3

class S3RepositoryFactory:
    def __init__(self):
        self.client = None

    def create_s3_client(self):
        if not self.client:
            self.client = boto3.client('s3')
        return self.client

    def get_supported_scheme(self):
        return {"s3"}

    def new_instance(self, name: str, uri: str) -> dict:
        scheme = uri.split("://")[0]
        if scheme.lower() != "s3":
            raise ValueError(f"Invalid s3 url: {uri}")
        
        client = self.create_s3_client()
        return {"name": name, "uri": uri, "client": client}
