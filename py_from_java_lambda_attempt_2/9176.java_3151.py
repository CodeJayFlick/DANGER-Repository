Here is the translation of the Java code into Python:

```Python
class BufferNode:
    def __init__(self, id: int, checkpoint: int):
        self.id = id
        self.checkpoint = checkpoint
        self.next_cached = None
        self.prev_cached = None
        self.next_version = None
        self.prev_version = None
        self.next_in_checkpoint = None
        self.prev_in_checkpoint = None
        self.locked = False
        self.empty = True
        self.modified = False
        self.is_dirty = False
        self.snapshot_taken = [False, False]

    def clear_snapshot_taken(self):
        self.snapshot_taken[0] = False
        self.snapshot_taken[1] = False

    def remove_from_cache(self):
        if self.prev_cached is not None:
            next_node = self.next_cached
            self.prev_cached.next_cached = next_node
            next_node.prev_cached = self.prev_cached
            self.next_cached = None
            self.prev_cached = None

    def add_to_cache(self, cache_head: 'BufferNode'):
        if cache_head is not None:
            prev_node = cache_head
            self.prev_cached = prev_node
            self.next_cached = prev_node.next_cached
            prev_node.next_cached.prev_cached = self
            prev_node.next_cached = self

    def remove_from_checkpoint(self):
        if self.prev_in_checkpoint is not None:
            next_node = self.next_in_checkpoint
            self.prev_in_checkpoint.next_in_checkpoint = next_node
            next_node.prev_in_checkpoint = self.prev_in_checkpoint
            self.next_in_checkpoint = None
            self.prev_in_checkpoint = None

    def add_to_checkpoint(self, checkpoint_head: 'BufferNode'):
        if checkpoint_head is not None:
            prev_node = checkpoint_head
            self.prev_in_checkpoint = prev_node
            self.next_in_checkpoint = prev_node.next_in_checkpoint
            prev_node.next_in_checkpoint.prev_in_checkpoint = self
            prev_node.next_in_checkpoint = self

    def remove_from_version(self):
        if self.prev_version is not None:
            next_node = self.next_version
            self.prev_version.next_version = next_node
            next_node.prev_version = self.prev_version
            self.next_version = None
            self.prev_version = None

    def add_to_version(self, version_head: 'BufferNode'):
        if version_head is not None:
            prev_node = version_head
            self.prev_version = prev_node
            self.next_version = prev_node.next_version
            prev_node.next_version.prev_version = self
            prev_node.next_version = self

    def __str__(self):
        return f"BufferNode(id={self.id}, checkpoint={self.checkpoint})"
```

Note that Python does not have a direct equivalent to Java's `final` keyword, so I did not include it in the translation. Also, Python is dynamically typed and does not require explicit type declarations for variables or method parameters like Java does.