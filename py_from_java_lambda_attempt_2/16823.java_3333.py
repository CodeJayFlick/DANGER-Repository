Here is the translation of the Java code to Python:
```python
import os
import logging

class HDFSFile(os.path):
    def __init__(self, pathname):
        super().__init__(pathname)
        self.hdfs_path = os.path.join(pathname)
        self.fs = None
        self.logger = logging.getLogger(__name__)

    @property
    def hdfs_path(self):
        return self._hdfs_path

    @hdfs_path.setter
    def hdfs_path(self, value):
        self._hdfs_path = value

    def set_conf_and_get_fs(self):
        conf = HDFSConfUtil.set_conf(Configuration())
        try:
            self.fs = os.path.get_file_system(conf)
        except IOException as e:
            self.logger.error("Failed to get HDFS file system", e)

    @property
    def absolute_path(self):
        return self.hdfs_path

    @property
    def path(self):
        return self.hdfs_path

    def length(self):
        try:
            return os.path.get_file_status(self.fs, self.hdfs_path).get_len()
        except IOException as e:
            self.logger.error("Failed to get file length", e)
            return 0

    def exists(self):
        try:
            return os.path.exists(self.fs, self.hdfs_path)
        except IOException as e:
            self.logger.error("Failed to check if file exists", e)
            return False

    def list_files(self):
        files = []
        for file_status in os.path.list_status(self.fs, self.hdfs_path):
            path = file_status.get_path()
            files.append(HDFSFile(path))
        return files

    @property
    def parent_file(self):
        return HDFSFile(os.path.dirname(self.hdfs_path))

    def create_new_file(self):
        try:
            return os.path.create_new_file(self.fs, self.hdfs_path)
        except IOException as e:
            self.logger.error("Failed to create new file", e)

    @property
    def is_directory(self):
        try:
            return os.path.exists(self.fs, self.hdfs_path) and os.path.get_file_status(self.fs, self.hdfs_path).is_directory()
        except IOException as e:
            self.logger.error("Failed to check if directory exists", e)
            return False

    @property
    def free_space(self):
        try:
            return os.path.get_status(self.fs).get_remaining()
        except IOException as e:
            self.logger.error("Failed to get free space", e)
            return 0

    @property
    def name(self):
        return os.path.basename(self.hdfs_path)

    @property
    def to_string(self):
        return str(self.hdfs_path)

    def rename_to(self, dest):
        try:
            return os.path.rename(self.fs, self.hdfs_path, dest)
        except IOException as e:
            self.logger.error("Failed to rename file", e)
            return False

    @property
    def buffered_reader(self, filePath):
        try:
            return BufferedReader(InputStreamReader(os.open(filePath)))
        except IOError as e:
            self.logger.error("Failed to get buffered reader for {}".format(filePath), e)

    @property
    def buffered_writer(self, filePath, append=False):
        try:
            return BufferedWriter(OutputStreamWriter(os.create(filePath)), append)
        except IOError as e:
            self.logger.error("Failed to get buffered writer for {}".format(filePath), e)

    @property
    def buffered_input_stream(self, filePath):
        try:
            return BufferedInputStream(os.open(filePath))
        except IOError as e:
            self.logger.error("Failed to get buffered input stream for {}".format(filePath), e)

    @property
    def buffered_output_stream(self, filePath):
        try:
            return BufferedOutputStream(os.create(filePath))
        except IOError as e:
            self.logger.error("Failed to get buffered output stream for {}".format(filePath), e)
```
Note that I've used the `os` module instead of Java's equivalent classes. Also, some methods have been modified or removed since they are not applicable in Python (e.g., `compareTo`, `equals`).