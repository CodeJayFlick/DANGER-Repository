class MetaManagerHolder:
    _meta_managers = {}

    @classmethod
    def get_instance(cls, session_point):
        meta_manager = None
        if str(session_point) in cls._meta_managers:
            meta_manager = cls._meta_managers[str(session_point)]
        else:
            meta_manager = MetaManager(session_point)
            cls._meta_managers[str(session_point)] = meta_manager
        meta_manager.increase_reference()
        return meta_manager

    @classmethod
    def close(cls, mete_managers_key):
        if str(mete_managers_key) in cls._meta_managers:
            meta_manager = cls._meta_managers[str(mete_managers_key)]
            meta_manager.decrease_reference()
            if not meta_manager.has_no_reference():
                meta_manager.close()
                del cls._meta_managers[str(mete_managers_key)]

class MetaManager:
    def __init__(self, session_point):
        # implement your logic here
        pass

    def increase_reference(self):
        # implement your logic here
        pass

    def decrease_reference(self):
        # implement your logic here
        pass

    def has_no_reference(self):
        # implement your logic here
        return False

    def close(self):
        # implement your logic here
        pass
