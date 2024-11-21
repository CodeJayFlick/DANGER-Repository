import collections
from ghidra_dbg_target import TargetObject
from ghidra_dbg_util import PathUtils

class DbgListElementsCommand:
    def __init__(self, manager, path, target_object):
        self.manager = manager
        self.path = path
        self.target_object = target_object
        self.updated_elements = []

    def complete(self, pending):
        return self.updated_elements

    def invoke(self):
        with self.manager.get_access() as access:
            updated_elements = []
            elements = access.get_elements(self.path)
            existing_elements = self.target_object.get_cached_elements()

            for obj in elements:
                search_key = obj.search_key
                el_key = PathUtils.make_key(search_key)

                if existing_elements.get(el_key):
                    proxy_element = existing_elements[el_key]
                    delegate = proxy_element.delegate
                    delegate.set_model_object(obj)
                else:
                    proxy_element = DelegateDbgModel2TargetObject(
                        self.target_object.model, self.target_object,
                        el_key, obj
                    )
                updated_elements.append(proxy_element)

            return updated_elements

class DelegateDbgModel2TargetObject:
    def __init__(self, model, target_object, key, obj):
        self.delegate = None  # todo: implement delegate logic
        self.model = model
        self.target_object = target_object
        self.key = key
        self.obj = obj

    @property
    def get_delegate(self):
        return self.delegate

    @get_delegate.setter
    def set_model_object(self, obj):
        self.obj = obj  # todo: implement delegate logic
