Here is the translation of the given Java code into equivalent Python:

```Python
class SkeletonFileSystem:
    def __init__(self, fs_fsrl: 'FSRLRoot', provider: 'ByteProvider'):
        self.fs_fsrl = fs_fsrl
        self.provider = provider
        self.fsih = FileSystemIndexHelper(self, fs_fsrl)

    def mount(self):
        # TODO: Customize how things in the file system are stored. The following should be 
        # treated as pseudo-code.
        for _ in range(10):  # MyMetadata[10]
            if monitor.is_cancelled():
                break
            self.fsih.store_file(metadata.path, fsih.get_file_count(), False, metadata.size, metadata)

    def close(self):
        ref_manager.on_close()
        if provider is not None:
            provider.close()
            provider = None
        fsih.clear()

    @property
    def name(self) -> str:
        return self.fs_fsrl.container.name

    @property
    def fs_rl_root(self) -> 'FSRLRoot':
        return self.fs_fsrl

    @property
    def is_closed(self):
        return provider is None

    @property
    def file_count(self) -> int:
        return fsih.get_file_count()

    @property
    def ref_manager(self) -> 'FileSystemRefManager':
        return ref_manager

    def lookup(self, path: str) -> 'GFile':
        return self.fsih.lookup(path)

    def get_byte_provider(self, file: 'GFile', monitor):
        # TODO: Get an ByteProvider for a file. The following is an example of how the metadata
        # might be used to get an sub-ByteProvider from a stored provider offset.
        metadata = self.fsih.get_metadata(file)
        if metadata:
            return ByteProviderWrapper(self.provider, metadata.offset, metadata.size, file.fs_rl_root)

    def get_listing(self, directory: 'GFile') -> List['GFile']:
        return self.fsih.get_listing(directory)

    def get_file_attributes(self, file: 'GFile', monitor) -> 'FileAttributes':
        metadata = self.fsih.get_metadata(file)
        if metadata:
            result = FileAttributes()
            result.add(FileAttributeType.NAME_ATTR, metadata.name)
            result.add(FileAttributeType.SIZE_ATTR, metadata.size)

    class MyFileSystemFactory(GFileSystemFactoryByteProvider[SkeletonFileSystem], GFileSystemProbeByteProvider):
        def create(self, target_fsrl: 'FSRLRoot', byte_provider: 'ByteProvider', fs_service: 'FileSystemService', monitor) -> SkeletonFileSystem:
            # TODO: Customize for the real file system.
            return SkeletonFileSystem(target_fsrl, byte_provider)

    class MyMetadata:
        def __init__(self):
            self.name = None
            self.path = None
            self.offset = 0
            self.size = 0

class FileSystemIndexHelper(T):
    def __init__(self, skeleton_file_system: 'SkeletonFileSystem', fs_fsrl: 'FSRLRoot'):
        self.skeleton_file_system = skeleton_file_system
        self.fs_fsrl = fs_fsrl
        # TODO: Customize for the real file system.

    def store_file(self, path: str, count: int, is_directory: bool, size: long, metadata):
        pass

    def get_metadata(self, file) -> 'MyMetadata':
        return None  # TODO: Get metadata from files in the real file system.