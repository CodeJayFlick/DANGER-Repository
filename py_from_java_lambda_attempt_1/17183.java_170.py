Here is the translation of the given Java code into Python:

```Python
class MetaUtils:
    def __init__(self):
        pass

    @staticmethod
    def split_path_to_detached_path(path: str) -> list[str]:
        nodes = []
        start_index = 0
        for i in range(len(path)):
            if path[i] == IoTDBConstant.PATH_SEPARATOR:
                node = path[start_index:i]
                if not node:
                    raise IllegalPathException(path)
                nodes.append(node)
                start_index = i + 1
                if start_index == len(path):
                    raise IllegalPathException(path)

        return [node for node in nodes]

    @staticmethod
    def get_storage_group_path_by_level(path: PartialPath, level: int) -> PartialPath:
        node_names = path.get_nodes()
        if len(node_names) <= level or not node_names[0] == IoTDBConstant.PATH_ROOT:
            raise IllegalPathException(path.get_full_path())

        storage_group_nodes = node_names[:level + 1]
        return PartialPath(storage_group_nodes)

    @staticmethod
    def get_multi_full_paths(node: IMNode) -> list[str]:
        if not node:
            return []

        last_node_list = []
        MetaUtils._collect_last_node(node, last_node_list)
        result = [node.get_full_path() for node in last_node_list]
        return result

    @staticmethod
    def _collect_last_node(node: IMNode, last_node_list: list[IMNode]):
        if not node:
            pass

        children = node.get_children()
        if not children:
            last_node_list.append(node)

        for child_node in children.values():
            MetaUtils._collect_last_node(child_node, last_node_list)


class PartialPath(list):
    def get_nodes(self) -> list[str]:
        return self


class IMNode:
    def __init__(self, full_path: str):
        self.full_path = full_path

    @property
    def children(self) -> dict[str, 'IMNode']:
        pass

    @children.setter
    def children(self, value: dict[str, 'IMNode']):
        self._children = value

    @property
    def get_children(self) -> dict[str, 'IMNode']:
        return self._children


class IllegalPathException(Exception):
    pass


IoTDBConstant.PATH_SEPARATOR = '/'
```

Note that Python does not have direct equivalent of Java's `@TestOnly` annotation. In the given code, I removed these annotations as they are specific to JUnit testing framework in Java and do not apply directly to Python.