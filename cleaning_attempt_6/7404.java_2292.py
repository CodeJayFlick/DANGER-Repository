class ISO9660FileSystem:
    def __init__(self, fsrl: 'FSRLRoot', fs_service: 'FileSystemService'):
        super().__init__(fsrl, fs_service)

# You can use this class like this:
iso9660_file_system = ISO9660FileSystem(None, None)
