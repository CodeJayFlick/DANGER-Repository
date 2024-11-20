class SimpleObjects:
    def __init__(self):
        self.container = None  # injected service

    @property
    def title(self) -> str:
        return "Simple Objects"

    def list_all(self) -> List[dict]:
        if not hasattr(self, 'container'):
            raise AttributeError("Container is not set")
        simple_objects = []
        for obj in self.container.all_instances(SimpleObject):
            simple_objects.append(obj.__dict__)
        return simple_objects

    @property
    def find_by_name(self) -> list:
        if not hasattr(self, 'container'):
            raise AttributeError("Container is not set")

        name = input("Enter the object's name: ")
        results = []
        for obj in self.container.all_matches(SimpleObject.find_by_name(name)):
            results.append(obj.__dict__)
        return results

    class CreateDomainEvent:
        def __init__(self, source: 'SimpleObjects', identifier: str, *args):
            super().__init__(source, identifier, args)

    @property
    def create(self) -> dict:
        if not hasattr(self, 'container'):
            raise AttributeError("Container is not set")

        name = input("Enter the object's name: ")
        obj = self.container.new_transient_instance(SimpleObject)
        obj['name'] = name
        self.container.persist_if_not_already(obj)
        return obj.__dict__
