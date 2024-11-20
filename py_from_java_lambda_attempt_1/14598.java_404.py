Here is a translation of the provided Java code into equivalent Python:

```Python
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
```

Note that this translation does not include all Java-specific features like annotations, domain services, or query default. It also doesn't cover the full functionality of the original code as it's a simplified version for demonstration purposes only.

In Python, we don't have direct equivalents to Java's `@DomainService`, `@Action`, and other annotations. Instead, you would typically define methods on your class that perform specific actions or operations.

The provided translation is based on the assumption that you want to create equivalent functionality in Python without using any third-party libraries or frameworks like Apache Isis.