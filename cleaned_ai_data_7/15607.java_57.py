import hashlib
from urllib.request import urlopen
from io import BytesIO
from zipfile import ZipFile
from typing import List, Dict

class JarRepository:
    def __init__(self, name: str, uri: str, file_name: str):
        self.name = name
        self.uri = uri
        self.file_name = file_name
        self.model_name = None
        self.artifact_id = None
        self.metadata = None
        self.resolved = False

    def is_remote(self) -> bool:
        return True

    def locate(self, mrl: str) -> Dict:
        if not self.resolved:
            self.get_metadata()
        return {'artifactId': self.artifact_id,
                'modelName': self.model_name}

    def resolve(self, mrl: str, filter: Dict) -> List[Dict]:
        artifacts = self.locate(mrl)
        if len(artifacts) == 0:
            return []
        return [artifacts]

    def get_resources(self) -> List[str]:
        metadata = self.get_metadata()
        resources = []
        for artifact in metadata['artifacts']:
            mrl = f"undefined({self.name}, {metadata['groupId']}, {artifact})"
            resources.append(mrl)
        return resources

    def download(self, tmp: str, base_uri: str, item: Dict, progress: int) -> None:
        try:
            response = urlopen(self.uri)
            zip_file = ZipFile(BytesIO(response.read()))
            logger.debug(f"Extracting artifact: {self.uri}...")
            save(zip_file, tmp, item, progress)
        except Exception as e:
            print(str(e))

    def get_metadata(self) -> Dict:
        if self.resolved:
            return {'artifactId': self.artifact_id,
                    'modelName': self.model_name}
        
        self.resolved = True
        metadata = {}
        artifact = {'name': self.model_name, 'arguments': {}}
        files = {}
        item = {'uri': self.uri, 'name': '', 'artifact': artifact, 'size': -1}
        files[self.artifact_id] = item
        artifact['files'] = files

        metadata['artifactId'] = self.artifact_id
        metadata['artifacts'] = [artifact]
        hash = hashlib.md5(self.uri.encode()).hexdigest()
        mrl = f"undefined({self.name}, {DefaultModelZoo.GROUP_ID}, {hash})"
        metadata['repositoryUri'] = mrl

        return metadata


def save(zip_file, tmp, item, progress):
    # Implement the logic to save the file
    pass


# Usage:
jar_repository = JarRepository("name", "uri", "file_name")
metadata = jar_repository.get_metadata()
print(metadata)
