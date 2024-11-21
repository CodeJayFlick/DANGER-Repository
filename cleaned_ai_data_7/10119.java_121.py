import os


class LocalFilesystemTestUtils:
    def __init__(self):
        pass

    @staticmethod
    def create_mangled_filesystem(root_path: str, is_versioned: bool, read_only: bool, enable_async_dispatching: bool) -> dict:
        if not os.path.exists(root_path):
            raise Exception(f"Root directory '{root_path}' does not exist.")
        
        return {"mangled_local_file_system": MangledLocalFileSystem(root_path, is_versioned, read_only, enable_async_dispatching)}

    @staticmethod
    def create_original_indexed_filesystem(root_path: str, is_versioned: bool, read_only: bool, enable_async_dispatching: bool) -> dict:
        if not os.path.exists(root_path):
            raise Exception(f"Root directory '{root_path}' does not exist.")
        
        return {"original_indexed_local_file_system": None}

    @staticmethod
    def create_v0_indexed_filesystem(root_path: str, is_versioned: bool, read_only: bool, enable_async_dispatching: bool) -> dict:
        if not os.path.exists(root_path):
            raise Exception(f"Root directory '{root_path}' does not exist.")
        
        return {"v0_indexed_local_file_system": IndexedLocalFileSystem(root_path, is_versioned, read_only, enable_async_dispatching, True)}

    @staticmethod
    def create_v1_indexed_filesystem(root_path: str, is_versioned: bool, read_only: bool, enable_async_dispatching: bool) -> dict:
        if not os.path.exists(root_path):
            raise Exception(f"Root directory '{root_path}' does not exist.")
        
        return {"v1_indexed_local_file_system": IndexedV1LocalFileSystem(root_path, is_versioned, read_only, enable_async_dispatching, True)}

    @staticmethod
    def create_root_dir(root_path: str) -> None:
        if not os.path.exists(root_path):
            try:
                os.makedirs(root_path)
            except Exception as e:
                raise IOException(f"Failed to create root directory '{root_path}': {str(e)}")


class MangledLocalFileSystem(dict):
    pass


class IndexedLocalFileSystem(MangledLocalFileSystem):
    def __init__(self, root_path: str, is_versioned: bool, read_only: bool, enable_async_dispatching: bool, v0: bool = False) -> None:
        super().__init__()


class IndexedV1LocalFileSystem(IndexedLocalFileSystem):
    pass


class IOException(Exception):
    pass
