Here's your Java code translated into Python:

```Python
class GroupVertex:
    def __init__(self):
        self.children = set()
        self.first = None

    @classmethod
    def group_vertices(cls, vertices):
        # the set of vertices given may include group nodes, we only want "real nodes"
        children_set = flatten(vertices)
        list_ = list(children_set)
        list_.sort(key=lambda x: x.name)
        return cls(list_, get_unique_id(list_), list_[0])

    def __init__(self, children, id, first):
        super().__init__()
        self.first = first
        self.children = children
        set_vertex_type("Collapsed Group")

    @classmethod
    def flatten(cls, vertices):
        set_ = set()
        for vertex in vertices:
            if isinstance(vertex, GroupVertex):
                set_.update(vertex.children)
            else:
                set_.add(vertex)
        return set_

    @classmethod
    def get_unique_id(cls, vertex_list):
        if len(vertex_list) > 6:  # MAX_IDS_TO_COMBINE = 6 in Java
            ids_not_shown_count = len(vertex_list) - 6
            return combine_ids(vertex_list[:6]) + "\n...\n +" + str(ids_not_shown_count) + " Others"
        else:
            return combine_ids(vertex_list)

    @classmethod
    def combine_ids(cls, vertices):
        return '\n'.join([vertex.name for vertex in vertices])

    def get_contained_vertices(self):
        return frozenset(self.children)

    def get_first(self):
        return self.first


def set_vertex_type(type_):  # This method is not used anywhere
    pass

# Usage:
group = GroupVertex.group_vertices(vertices)
print(group.get_contained_vertices())
print(group.get_first())

```

Note: Python does not have direct equivalent of Java's `AttributedVertex` class. It has been replaced with a simple Python class in the above code.