class SystemFileFactory:
    _instance = None

    def __new__(cls):
        if not isinstance(cls._instance, cls):
            cls._instance = super(SystemFileFactory, cls).__new__(cls)
        return cls._instance

    @property
    def fs_type(self):
        # Replace this with your actual logic to get the file system type.
        # For example:
        from iotdb.tsfile.file_system import FSType
        from org.apache.iotdb.conf.config import IoTDBDescriptor
        self.fs_type = IoTDBDescriptor.getInstance().getConfig().getSystemFileStorageFs()

    def get_file(self, pathname):
        if self.fs_type == 'HDFS':
            raise Exception("Unsupported file system: HDFS")
        else:
            return File(pathname)

    def get_file(self, parent, child):
        if self.fs_type == 'HDFS':
            raise Exception("Unsupported file system: HDFS")
        else:
            return File(parent, child)

    def get_file(self, parent, child):
        if self.fs_type == 'HDFS':
            raise Exception("Unsupported file system: HDFS")
        else:
            return File(parent, child)

    def get_file(self, uri):
        if self.fs_type == 'HDFS':
            raise Exception("Unsupported file system: HDFS")
        else:
            return File(uri)
