import os
from hashlib import md5
from datetime import date

class LocalFileSystem:
    FSTYPE = "file"

    def __init__(self):
        self.empty_dir = []
        self.fs_fsrl = None
        self.ref_manager = FileSystemRefManager(self)
        self.file_fingerprint_to_md5_map = {}

    @staticmethod
    def make_global_root_fs():
        return LocalFileSystem()

    def is_same_fs(self, fsrl):
        return self.fs_fsrl == fsrl.get_fs()

    def get_sub_file_system(self, fsrl):
        if self.is_local_subdir(fsrl):
            local_dir = self.get_local_file(fsrl)
            return LocalFileSystemSub(local_dir, self)
        return None

    def is_local_subdir(self, fsrl):
        if not self.is_same_fs(fsrl):
            return False
        local_file = os.path.join(fsrl.get_path(), "")
        return os.path.isdir(local_file)

    def get_local_file(self, fsrl):
        if not self.is_same_fs(fsrl):
            raise Exception("FSRL does not specify local file")
        return os.path.abspath(os.path.realpath(fsrl.get_path()))

    def get_local_fsrl(self, f):
        return FSRLRoot().with_path(f)

    @property
    def name(self):
        return "Root Filesystem"

    def close(self):
        pass

    def is_static(self):
        return False

    def get_listing(self, directory):
        results = []
        if directory is None:
            for root in os.listdir():
                results.append(GFileImpl.from_fsrl(self, None, self.get_local_fsrl(root), True, 0))
        else:
            local_dir = os.path.abspath(os.path.realpath(directory.get_path()))
            if not os.path.isdir(local_dir) or os.path.islink(local_dir):
                return []
            files = [f for f in os.listdir(local_dir) if os.path.isfile(os.path.join(local_dir, f)) or os.path.isdir(os.path.join(local_dir, f))]
            for file in files:
                results.append(GFileImpl.from_fsrl(self, directory, self.get_local_fsrl(file), os.path.isdir(os.path.join(local_dir, file)), os.path.getsize(os.path.join(local_dir, file))))
        return results

    def get_file_attributes(self, file):
        f = os.path.abspath(os.path.realpath(file))
        if not os.path.exists(f):
            raise Exception("File does not exist")
        type_ = FileType.file_type(f)
        sym_link_dest = None
        try:
            sym_link_dest = os.readlink(f) if type_ == "symbolic link" else None
        except FileNotFoundError:
            pass
        return FileAttributes(
            name=FileAttribute(name="name", value=os.path.basename(f)),
            file_type=FileAttribute(type_, str(type_)),
            size=FileAttribute(size, f"{os.path.getsize(f)} bytes"),
            modified_date=FileAttribute(modified_date, date.fromtimestamp(os.path.getmtime(f))),
            sym_link_dest=FileAttribute(sym_link_dest) if sym_link_dest else None
        )

    def get_fsrl(self):
        return self.fs_fsrl

    @staticmethod
    def file_to_file_type(p):
        if os.path.islink(p):
            return "symbolic link"
        elif os.path.isdir(p):
            return "directory"
        elif os.path.isfile(p):
            return "file"

class FileAttributes:
    def __init__(self, **kwargs):
        self.attributes = kwargs

    @property
    def name(self):
        return self.attributes.get("name", "")

    @property
    def file_type(self):
        return self.attributes.get("file type")

    @property
    def size(self):
        return int(self.attributes.get("size", 0))

    @property
    def modified_date(self):
        return date.fromtimestamp(int(self.attributes.get("modified date", 0)))

    @property
    def sym_link_dest(self):
        return self.attributes.get("sym link dest")

class LocalFileSystemSub:
    def __init__(self, local_dir, fs):
        self.local_dir = os.path.abspath(os.path.realpath(local_dir))
        self.fs = fs

    def get_listing(self):
        results = []
        if not os.path.isdir(self.local_dir) or os.path.islink(self.local_dir):
            return []
        files = [f for f in os.listdir(self.local_dir) if os.path.isfile(os.path.join(self.local_dir, f)) or os.path.isdir(os.path.join(self.local_dir, f))]
        for file in files:
            results.append(GFileImpl.from_fsrl(fs, None, fs.get_local_fsrl(file), os.path.isdir(os.path.join(self.local_dir, file)), os.path.getsize(os.path.join(self.local_dir, file))))
        return results

class FileSystemRefManager:
    def __init__(self, fs):
        self.fs = fs
