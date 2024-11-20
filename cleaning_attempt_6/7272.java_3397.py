import os
from abc import ABCMeta, abstractmethod


class CpioFileSystem:
    def __init__(self, fs_fsrl, provider, fs_service):
        self.fs_service = fs_service
        self.fs_fsrl = fs_fsrl
        self.provider = provider

    @abstractmethod
    def close(self):
        pass

    def get_fsrl(self):
        return self.fs_fsrl

    def get_name(self):
        return os.path.basename(self.fs_fsrl.get_container().get_name())

    def is_closed(self):
        return self.provider is None

    def get_ref_manager(self):
        return self.fs_service.get_file_system_ref_manager()

    def list_files(self, directory):
        if not isinstance(directory, str):
            raise ValueError("Directory must be a string")
        try:
            with open(os.path.join(self.fs_fsrl.get_container().get_path(), directory), 'rb') as f:
                cpio_archive = CpioArchive(f)
                return [entry.name for entry in cpio_archive.entries]
        except FileNotFoundError:
            return []

    def lookup_file(self, path):
        if not isinstance(path, str):
            raise ValueError("Path must be a string")
        try:
            with open(os.path.join(self.fs_fsrl.get_container().get_path(), path), 'rb') as f:
                cpio_archive = CpioArchive(f)
                return [entry for entry in cpio_archive.entries if entry.name == path][0]
        except FileNotFoundError:
            return None

    def get_file_attributes(self, file):
        attributes = {}
        with open(os.path.join(self.fs_fsrl.get_container().get_path(), file), 'rb') as f:
            cpio_archive = CpioArchive(f)
            for entry in cpio_archive.entries:
                if entry.name == file:
                    attributes['name'] = entry.name
                    attributes['size'] = entry.size
                    attributes['modified_date'] = entry.modified_date
                    attributes['user_id'] = entry.user_id
                    attributes['group_id'] = entry.group_id
                    attributes['mode'] = hex(entry.mode)
                    attributes['inode'] = hex(entry.inode)
                    attributes['format'] = hex(entry.format)
                    try:
                        attributes['device_id'] = hex(entry.device)
                        attributes['remote_device'] = hex(entry.remote_device)
                    except Exception as e:
                        pass
                    try:
                        attributes['checksum'] = hex(entry.checksum)
                    except Exception as e:
                        pass
        return attributes

    def get_byte_provider(self, file):
        if not isinstance(file, str):
            raise ValueError("File must be a string")
        with open(os.path.join(self.fs_fsrl.get_container().get_path(), file), 'rb') as f:
            cpio_archive = CpioArchive(f)
            for entry in cpio_archive.entries:
                if entry.name == file:
                    return self.provider
        raise ValueError("File not found")


class CpioArchive:
    def __init__(self, stream):
        self.stream = stream

    @property
    def entries(self):
        try:
            with self.stream as f:
                cpio_archive_entry = None
                while True:
                    entry = next(CpioArchiveEntry(f), None)
                    if entry is not None:
                        yield entry
                    else:
                        break
        except Exception as e:
            pass


class CpioArchiveEntry:
    def __init__(self, stream):
        self.stream = stream

    @property
    def name(self):
        return ''

    @property
    def size(self):
        return 0

    @property
    def modified_date(self):
        return None

    @property
    def user_id(self):
        return 0

    @property
    def group_id(self):
        return 0

    @property
    def mode(self):
        return 0

    @property
    def inode(self):
        return 0

    @property
    def format(self):
        return 0

    @property
    def device(self):
        return None

    @property
    def remote_device(self):
        return None

    @property
    def checksum(self):
        return None


class GFile:
    pass


class FSRLRoot:
    def __init__(self, container):
        self.container = container

    @property
    def get_container(self):
        return self.container

    @property
    def get_path(self):
        return ''


class FileSystemService:
    def __init__(self):
        pass

    def get_file_system_ref_manager(self):
        return None


def main():
    fs_fsrl = FSRLRoot('')
    provider = ''
    fs_service = FileSystemService()
    cpio_file_system = CpioFileSystem(fs_fsrl, provider, fs_service)
    # Use the file system
    print(cpio_file_system.get_name())
    print(cpio_file_system.is_closed())


if __name__ == "__main__":
    main()


