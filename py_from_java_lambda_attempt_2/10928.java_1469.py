Here's your Java code translated into Python:

```Python
from pathlib import Path
import urllib.parse

class ImageLocation:
    def __init__(self, source_file, image_src):
        self.source_file = source_file
        self.image_src = image_src
        self.resolved_path = None
        self.resolved_uri = None
        self.is_remote = False
        self.is_runtime = False
        self.invalid_runtime_image = False

    @classmethod
    def create_local_location(cls, source_file, image_src, resolved_uri, resolved_path):
        instance = cls(source_file, image_src)
        instance.resolved_uri = resolved_uri
        instance.resolved_path = resolved_path
        instance.is_remote = False
        instance.is_runtime = False
        return instance

    @classmethod
    def create_runtime_location(cls, source_file, image_src, resolved_uri, resolved_path):
        instance = cls(source_file, image_src)
        instance.resolved_uri = resolved_uri
        instance.resolved_path = resolved_path
        instance.is_remote = False
        instance.is_runtime = True
        return instance

    @classmethod
    def create_invalid_runtime_location(cls, source_file, image_src):
        instance = cls(source_file, image_src)
        instance.resolved_uri = None
        instance.resolved_path = None
        instance.is_remote = False
        instance.is_runtime = True
        instance.invalid_runtime_image = True
        return instance

    @classmethod
    def create_remote_location(cls, source_file, image_src, resolved_uri):
        instance = cls(source_file, image_src)
        instance.resolved_uri = resolved_uri
        instance.resolved_path = None
        instance.is_remote = True
        instance.is_runtime = False
        return instance

    @property
    def source_file(self):
        return self._source_file

    @source_file.setter
    def source_file(self, value):
        self._source_file = value

    @property
    def image_src(self):
        return self._image_src

    @image_src.setter
    def image_src(self, value):
        self._image_src = value

    @property
    def resolved_path(self):
        return self._resolved_path

    @resolved_path.setter
    def resolved_path(self, value):
        self._resolved_path = value

    @property
    def resolved_uri(self):
        return self._resolved_uri

    @resolved_uri.setter
    def resolved_uri(self, value):
        self._resolved_uri = value

    @property
    def is_remote(self):
        return self._is_remote

    @is_remote.setter
    def is_remote(self, value):
        self._is_remote = value

    @property
    def is_runtime(self):
        return self._is_runtime

    @is_runtime.setter
    def is_runtime(self, value):
        self._is_runtime = value

    @property
    def invalid_runtime_image(self):
        return self._invalid_runtime_image

    @invalid_runtime_image.setter
    def invalid_runtime_image(self, value):
        self._invalid_runtime_image = value

    def __str__(self):
        if self.is_remote:
            remote_str = "remote"
        else:
            remote_str = "local"

        if self.is_runtime:
            runtime_str = "runtime"
        else:
            runtime_str = ""

        return f"{{\n\tsource file: {self.source_file},\n\tsrc: {self.image_src},\n\turi: {self.resolved_uri},\n"path: {self.resolved_path},\n\tis runtime: {self.is_runtime},\n\tis remote: {remote_str}\n}}"
```

Note that Python does not have a direct equivalent to Java's `@Override` annotation. The method overriding is done by the name of the method, so you don't need an explicit override declaration in your code.