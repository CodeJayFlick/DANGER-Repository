import threading
from abc import ABCMeta, abstractmethod

class RemoteBufferFileImpl:
    instanceOwnerMap = {}
    instancePathMap = {}

    def __init__(self, buffer_file, owner, associated_file_path):
        self.buffer_file = buffer_file
        self.owner = owner
        self.associated_file_path = associated_file_path
        if not (owner and associated_file_path):
            raise ValueError("Missing one or more required arguments")
        self.client_host = RepositoryManager.getRMIClient()
        self.add_instance(self)

    @staticmethod
    def get_file_path_key(repo_name, file_path):
        return f"{repo_name}:{file_path}"

    @classmethod
    def add_instance(cls, rbf):
        owner_list = cls.instanceOwnerMap.setdefault(rbf.owner, [])
        if not owner_list:
            owner_list.append(rbf)
        path_key = cls.get_file_path_key(rbf.owner.repository.name, rbf.associated_file_path)
        list_ = cls.instancePathMap.setdefault(path_key, [])
        if not list_:
            list_.append(rbf)
        rbf.owner.fire_open_file_count_changed()

    @classmethod
    def remove_owner_instance(cls, rbf):
        owner_list = cls.instanceOwnerMap.get(rbf.owner)
        if owner_list and owner_list.remove(rbf) and not owner_list:
            del cls.instanceOwnerMap[rbf.owner]
        rbf.owner.fire_open_file_count_changed()

    @classmethod
    def remove_path_instance(cls, rbf):
        path_key = cls.get_file_path_key(rbf.owner.repository.name, rbf.associated_file_path)
        list_ = cls.instancePathMap.get(path_key)
        if list_ and list_.remove(rbf) and not list_:
            del cls.instancePathMap[path_key]

    @classmethod
    def get_open_file_count(cls, owner):
        return len(cls.instanceOwnerMap.get(owner))

    def __init__(self, buffer_file, owner, associated_file_path):
        super().__init__()
        self.buffer_file = buffer_file
        self.owner = owner
        self.associated_file_path = associated_file_path

    @abstractmethod
    def dispose(self):
        pass

class RepositoryHandleImpl:
    def fire_open_file_count_changed(self):
        pass

def getRMIClient():
    return "localhost"

class RemoteBufferFileHandle(metaclass=ABCMeta):

    def __init__(self, buffer_file, owner, associated_file_path):
        super().__init__()
        self.buffer_file = buffer_file
        self.owner = owner
        self.associated_file_path = associated_file_path

    @abstractmethod
    def dispose(self):
        pass

class RemoteBufferFileHandleImpl(RemoteBufferFileHandle):

    def __init__(self, buffer_file, owner, associated_file_path):
        super().__init__(buffer_file, owner, associated_file_path)

    def dispose(self):
        if self.buffer_file:
            try:
                unexport_object(self)
            except NoSuchObjectException as e:
                pass
            remove_owner_instance(self)
            remove_path_instance(self)
            self.buffer_file.dispose()
            self.buffer_file = None

def getRMIClient():
    return "localhost"

class RepositoryManager:

    @classmethod
    def getRMIClient(cls):
        return "localhost"
