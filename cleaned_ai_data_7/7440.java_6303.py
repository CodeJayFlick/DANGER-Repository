import io
from collections import defaultdict


class YAFFS2FileSystem:
    def __init__(self, file_system_name: str, provider):
        self.map = {}
        self.map2 = {}

    @property
    def root(self):
        return GFileImpl(None)

    def is_valid(self) -> bool:
        bytes_ = provider.read_bytes(0, YAFFS2Constants.MAGIC_SIZE)
        if (bytes_[0] == 3 and bytes_[10] == 0):
            return True

    def open(self):
        yaffs2_input = YAFFS2InputStream(provider.get_stream(0))
        while not monitor.is_cancelled():
            header_entry = yaffs2_input.next_header_entry()
            if header_entry is None:
                break
            self.store_entry(header_entry, monitor)

    def close(self):
        self.map.clear()
        self.map2.clear()

    def get_listing(self, directory: 'GFile') -> list:
        roots = []
        for obj_id in self.map.keys():
            parent_file = self.map[obj_id].parent_file
            if parent_file is not None and (directory == root or parent_file == root):
                file = self.map[obj_id]
                roots.append(file)
        return roots

    def get_byte_provider(self, file: 'GFile', monitor) -> io.BytesIO:
        entry = self.map2.get(file)
        if entry.is_directory():
            raise IOException(f"{file.name} is a directory")
        file_offset = entry.file_offset
        size = entry.size
        try:
            with YAFFS2InputStream(provider.get_stream(0)) as yaffs2_input:
                data = yaffs2_input.entry_data(file_offset, size)
                return io.BytesIO(data), file.fsrl
        except Exception as e:
            raise

    def store_entry(self, entry: 'YAFFS2Entry', monitor):
        if entry is None:
            return
        monitor.set_message(entry.name)

        parent_object_id = entry.parent_object_id
        object_id = entry.object_id
        parent_file = self.map.get(parent_object_id) or root

        if (object_id == 1 and parent_object_id == 1):
            return

        file = GFileImpl.from_filename(self, parent_file, entry.name,
                                        entry.is_directory(), entry.size, None)
        self.map[entry.object_id] = file
        self.map2[file] = entry


class YAFFS2InputStream:
    def __init__(self, stream):
        self.stream = stream

    def next_header_entry(self) -> 'YAFFS2Entry':
        # todo: implement this method
        pass

    def get_entry_data(self, file_offset: int, size: int) -> bytes:
        # todo: implement this method
        pass


class GFileImpl:
    @classmethod
    def from_filename(cls, fs, parent_file, name, is_directory, size):
        return cls(fs, parent_file, name, is_directory, size)


class IOException(Exception):
    pass

# usage example:

monitor = TaskMonitor()
provider = ByteProvider()

yaffs2_fs = YAFFS2FileSystem("YAFFS2", provider)
if yaffs2_fs.is_valid():
    try:
        yaffs2_fs.open(monitor)
    except CancelledException as e:
        print(f"Cancelled: {e}")
    finally:
        yaffs2_fs.close()
else:
    print("Invalid file system")
