Here is the translation of the Java code to Python:
```python
import os
import hashlib
from urllib.parse import urlparse, urlunparse
from typing import List, Dict

class HdfsRepository:
    def __init__(self, name: str, uri: str, config):
        self.name = name
        self.uri = uri
        self.config = config
        self.prefix = os.path.dirname(uri)
        self.artifact_id = None
        self.model_name = None
        self.metadata = None
        self.resolved = False

    def is_remote(self) -> bool:
        return True

    def locate(self, mrl: str) -> Dict[str, Any]:
        if not self.resolved:
            self.get_metadata()
        return self.metadata

    def resolve(self, mrl: str, filter: Dict[str, str]) -> Artifact:
        metadata = self.locate(mrl)
        if metadata is None:
            return None
        artifacts = metadata["artifacts"]
        if len(artifacts) == 0:
            return None
        return artifacts[0]

    def download(self, tmp_path: Path, base_uri: str, item: Artifact.Item, progress):
        fs = self.get_file_system()
        path = os.path.join(self.prefix, item.uri)
        logger.debug(f"Downloading artifact: {path}...")
        try:
            with fs.open(path) as is:
                save(is, tmp_path, item, progress)
        except Exception as e:
            raise

    def get_resources(self) -> List[MRL]:
        metadata = self.get_metadata()
        if metadata and len(metadata["artifacts"]) > 0:
            mrl = MRL(model=Application.UNDEFINED, group_id=metadata["group_id"], artifact_id=metadata["artifact_id"])
            return [mrl]
        return []

    def get_metadata(self) -> Dict[str, Any]:
        if self.resolved:
            return self.metadata
        self.resolved = True
        metadata = {"artifacts": []}
        files = list_files()
        if files is None:
            logger.debug(f"No object found in hdfs: {self.uri}")
            return {}
        artifact_id = hashlib.md5(self.uri.encode()).hexdigest()
        mrl = MRL(model=Application.UNDEFINED, group_id="DefaultModelZoo", artifact_id=artifact_id)
        metadata["repository_uri"] = urlunparse((mrl.scheme, mrl.netloc, mrl.path, "", ""))
        metadata["artifact_id"] = self.artifact_id
        metadata["artifacts"].append(files[0])
        return metadata

    def list_files(self) -> Artifact:
        fs = self.get_file_system()
        status = fs.list_status(os.path.join(self.prefix))
        if len(status) == 0:
            return None
        artifact = {"name": self.model_name, "arguments": {}}
        files = {}
        for st in status:
            item = {"uri": os.path.join(self.prefix, st.name), "size": st.length, "artifact": artifact}
            if not st.isDirectory():
                return Artifact(item)
            key = st.name
            if not key.endswith("/"):
                item["name"] = ""
                files[key] = item
        return Artifact(files)

    def get_file_system(self) -> FileSystem:
        # implement this method to create a Hadoop file system instance
        pass

class MRL:
    def __init__(self, model: str, group_id: str, artifact_id: str):
        self.model = model
        self.group_id = group_id
        self.artifact_id = artifact_id

class Artifact:
    def __init__(self, files=None):
        self.name = None
        self.arguments = {}
        if files is not None:
            self.files = files

def save(is: InputStream, tmp_path: Path, item: Artifact.Item, progress):
    # implement this method to save the artifact
    pass

logger = logging.getLogger(__name__)
```
Note that I've used Python's built-in `os` and `hashlib` modules for file system operations and hash calculations. Additionally, I've replaced Java's `Logger` with Python's built-in `logging` module.

Also, please note that this is a translation of the code to Python, but it may not be 100% equivalent due to differences in language syntax and semantics.