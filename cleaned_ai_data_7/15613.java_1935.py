import json
from datetime import timedelta, date
from urllib.request import urlopen
from io import BufferedReader, BufferedWriter
from os.path import join, exists, mkdir, getsize
from os import remove, rename
from collections import defaultdict

class RemoteRepository:
    ONE_DAY = timedelta(days=1)

    def __init__(self, name: str, uri: str):
        self.name = name
        self.uri = uri
        self.resources = []

    def is_remote(self) -> bool:
        return True

    def locate(self, mrl: dict) -> dict or None:
        mrl_uri = URI(mrl['uri'])
        file_path = join(self.uri, *mrl_uri.path.split('/')) + '/metadata.json'
        cache_dir = self.get_cache_directory()
        if not exists(cache_dir):
            mkdir(cache_dir)
        cache_file = join(cache_dir, 'metadata.json')
        if exists(cache_file):
            try:
                with open(cache_file) as reader:
                    metadata = json.load(reader)
                    metadata['lastUpdated'] = date.today().strftime('%Y-%m-%d')
                    return metadata
            except Exception as e:
                print(f"Error: {e}")
                pass

        tmp = join(self.get_cache_directory(), 'metadata.tmp.json')
        try:
            with urlopen(file_path) as response:
                json_data = response.read().decode('utf-8')
                metadata = json.loads(json_data)
                metadata['lastUpdated'] = date.today().strftime('%Y-%m-%d')
                with open(tmp, mode='w') as writer:
                    json.dump(metadata, writer)
            rename(tmp, cache_file)
            return metadata
        finally:
            if exists(tmp):
                remove(tmp)

    def resolve(self, mrl: dict, filter: dict) -> dict or None:
        metadata = self.locate(mrl)
        version_range = VersionRange.parse(mrl['version'])
        artifacts = [artifact for artifact in metadata.get('artifacts', []) 
                     if (filter.get('minVersion') and 
                         Version(artifact['version']) >= Version(filter['minVersion'])) or
                        (filter.get('maxVersion') and 
                         Version(artifact['version']) <= Version(filter['maxVersion']))
        return max(artifacts, key=lambda x: Version(x['version']))

    def get_resources(self) -> list:
        if not self.resources:
            return []
        return self.resources

    def add_resource(self, mrl: dict):
        if not self.resources:
            self.resources = [mrl]
        else:
            self.resources.append(mrl)

class URI(str): pass
class Version(int): pass
