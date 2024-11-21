import os
import hashlib
from typing import List, Dict

class SimpleRepository:
    def __init__(self, name: str, uri: str, path: str):
        self.name = name
        self.uri = uri
        self.path = path
        self.is_remote = False
        if not os.path.exists(path):
            self.is_remote = True
        self.artifact_id = None
        self.model_name = None

    def is_remote(self) -> bool:
        return self.is_remote

    def get_base_uri(self) -> str:
        return self.uri

    def locate(self, mrl: str) -> Dict:
        if not os.path.exists(self.path):
            logger.debug(f"Specified path doesn't exists: {self.path}")
            return {}
        metadata = {"repositoryUri": "", "artifactId": self.artifact_id}
        artifact = {"name": self.model_name, "arguments": {}}
        files = {}
        if self.is_remote:
            item = {"uri": self.uri, "name": "", "artifact": artifact, "size": os.path.getsize(self.path)}
            files[self.artifact_id] = item
            metadata["repositoryUri"] = mrl
        else:
            if os.path.isdir(self.path):
                for f in os.listdir(self.path):
                    file_path = os.path.join(self.path, f)
                    item = {"name": f, "size": os.path.getsize(file_path), "artifact": artifact}
                    files[f] = item
            else:
                logger.warn("Simple repository pointing to a non-archive file.")
        metadata["artifacts"] = [artifact]
        return metadata

    def resolve(self, mrl: str) -> Dict:
        if not os.path.exists(self.path):
            logger.debug(f"Specified path doesn't exists: {self.path}")
            return {}
        metadata = self.locate(mrl)
        artifact = next(iter(metadata["artifacts"]))
        return artifact

    def get_resource_directory(self, artifact: str) -> str:
        if not os.path.exists(self.path):
            logger.debug(f"Specified path doesn't exists: {self.path}")
            return ""
        if self.is_remote:
            return super().get_resource_directory(artifact)
        else:
            return self.path

    def download(self, tmp_path: str, base_uri: str, item: Dict, progress: int) -> None:
        logger.debug(f"Extracting artifact: {self.path}...")
        try:
            with open(tmp_path, "wb") as f:
                f.write(open(self.path, "rb").read())
        except Exception as e:
            print(e)

    def prepare(self, artifact: str, progress: int) -> None:
        if self.is_remote:
            super().prepare(artifact, progress)
        else:
            logger.debug("Skip prepare for local repository.")

    def get_cache_directory(self) -> str:
        if not os.path.exists(self.path):
            logger.debug(f"Specified path doesn't exists: {self.path}")
            return ""
        if self.is_remote:
            return super().get_cache_directory()
        else:
            return self.path

    def resolve_path(self, item: Dict, path: str) -> str:
        if not os.path.exists(self.path):
            logger.debug(f"Specified path doesn't exists: {self.path}")
            return ""
        if self.is_remote:
            return super().resolve_path(item, path)
        else:
            return os.path.join(self.path, item["name"])

    def get_resources(self) -> List[str]:
        if not os.path.exists(self.path):
            logger.debug(f"Specified path doesn't exists: {self.path}")
            return []
        mrl = f"{self.uri}/{self.artifact_id}"
        return [mrl]

def md5hash(path: str) -> str:
    hash_md5 = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

if __name__ == "__main__":
    repository = SimpleRepository("test", "https://example.com", "/path/to/repository")
    metadata = repository.locate("")
    print(metadata)

