import boto3
from botocore.exceptions import SdkException
from typing import List, Dict

class S3Repository:
    def __init__(self, name: str, uri: str):
        self.name = name
        self.uri = uri
        self.client = boto3.client('s3')
        self.bucket = uri.split('//')[-1].split('/')[0]
        self.prefix = '/' + '/'.join(uri.split('//')[-1].split('/')[:-1]) if uri.split('//')[-1] else ''
        self.artifact_id = None
        self.model_name = None

    def is_remote(self) -> bool:
        return True

    def locate(self, mrl: str) -> Dict[str, any]:
        return self.get_metadata()

    def resolve(self, mrl: str, filter: dict) -> any:
        metadata = self.locate(mrl)
        if not metadata:
            return None
        artifacts = list(metadata.values())
        if not artifacts:
            return None
        return artifacts[0]

    def download(self, tmp_path: str, base_uri: str, item: Dict[str, any], progress: int) -> None:
        key = item['uri']
        logger.debug(f"Downloading artifact from s3://{self.bucket}/{key}...")
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=key)
            with open(tmp_path, 'wb') as f:
                for chunk in response['Body'].iter_chunks():
                    f.write(chunk)
        except SdkException as e:
            logger.error(f"Failed to download artifact: {e}")

    def get_metadata(self) -> Dict[str, any]:
        if self.resolved:
            return self.metadata
        try:
            self.resolved = True
            metadata = {}
            for obj in self.client.list_objects(Bucket=self.bucket, Prefix=self.prefix)['Contents']:
                key = obj['Key']
                item = {'uri': key}
                if not key.endswith('/'):
                    item['size'] = obj['Size']
                    item['type'] = 'file'  # or dir
                    metadata[key] = item
            self.metadata = metadata
        except SdkException as e:
            logger.error(f"Failed to scan s3 bucket: {e}")
        return self.metadata

    def list_files(self) -> Dict[str, any]:
        files = {}
        for obj in self.client.list_objects(Bucket=self.bucket, Prefix=self.prefix)['Contents']:
            key = obj['Key']
            if not key.endswith('/'):
                item = {'uri': key}
                item['size'] = obj['Size']
                item['type'] = 'file'  # or dir
                files[key] = item
        return files

    def model(self, application: str, group_id: str, artifact_id: str) -> Dict[str, any]:
        mrl = {'application': application, 'group_id': group_id, 'artifact_id': artifact_id}
        return mrl
