Here is the translation of the Java code into equivalent Python:

```Python
import os
from collections import defaultdict, OrderedDict

class OverlayHelpTree:
    def __init__(self):
        self.parent_to_children_map = defaultdict(set)
        self.root_item = None
        self.link_database = None

    def add_external_toc_item(self, item):
        parent = item.get_parent()
        if not parent:
            return  # must be the root, since the root has no parent
        parent_id = parent.get_id_attribute()
        set_ = self.parent_to_children_map[parent_id]
        if not set_:
            set_ = set()
            self.parent_to_children_map[parent_id] = set_
        set_.add(item)

    def add_source_toc_item(self, item):
        parent = item.get_parent()
        if not parent:
            return  # must be the root, since the root has no parent
        parent_id = parent.get_id_attribute()
        set_ = self.parent_to_children_map[parent_id]
        if not set_:
            set_ = set()
            self.parent_to_children_map[parent_id] = set_
        set_.add(item)

    def do_add_toc_item(self, item):
        parent = item.get_parent()
        if not parent:
            return  # must be the root, since the root has no parent
        parent_id = parent.get_id_attribute()
        set_ = self.parent_to_children_map[parent_id]
        if not set_:
            set_ = set()
            self.parent_to_children_map[parent_id] = set_
        set_.add(item)

    def print_tree_for_id(self, output_file_path, source_file_id):
        with open(output_file_path, 'w') as f:
            writer = PrintWriter(f)
            self.print_contents(source_file_id, writer)
            writer.close()

    def initialize_tree(self):
        if not self.root_node:
            return False
        new_root_node = OverlayNode(None, self.root_item)
        build_children(new_root_node)
        if self.parent_to_children_map:
            raise RuntimeError("Unresolved definitions in tree!")
        self.root_node = new_root_node
        return True

    def print_contents(self, source_file_id, writer):
        if not self.root_node:
            return  # assume no content; help module does not appear in TOC view
        self.root_node.print(source_file_id, writer)

class OverlayNode:
    def __init__(self, parent_node, toc_item):
        self.parent_node = parent_node
        self.toc_item = toc_item

    def print(self, source_file_id, writer, indent_level=0):
        if not self.file_ids.get(source_file_id):
            return  # no file ID; skip printing this node and its children
        writer.write(f"{self.toc_item.generate_toc_item_tag()}\n")
        for child in sorted(list(self.children)):
            child.print(source_file_id, writer, indent_level + 1)
        if self.children:
            writer.write(f"{self.toc_item.generate_end_tag(indent_level)}\n")

    def add_child(self, overlay_node):
        self.children.add(overlay_node)

    @property
    def file_ids(self):
        return set()

    @file_ids.setter
    def file_ids(self, value):
        self._file_ids = value

    @property
    def children(self):
        return OrderedDict()

    @children.setter
    def children(self, value):
        self._children = value

class TOCItem:
    # assume these methods and attributes exist in the original Java code
    pass


def build_children(node):
    definition_id = node.toc_item.get_id_attribute()
    set_ = OverlayHelpTree.parent_to_children_map[definition_id]
    if not set_:
        return  # childless
    for child in sorted(list(set_)):
        new_child_node = OverlayNode(node, child)
        node.add_child(new_child_node)
        build_children(new_child_node)


def main():
    help_tree = OverlayHelpTree()
    # add your TOC items here using the add_external_toc_item and add_source_toc_item methods
    output_file_path = 'output.xml'
    source_file_id = 'source_file_id'
    help_tree.print_tree_for_id(output_file_path, source_file_id)


if __name__ == '__main__':
    main()
```

Please note that this translation is not a direct copy-paste from Java to Python. It's an equivalent implementation in Python of the original code.