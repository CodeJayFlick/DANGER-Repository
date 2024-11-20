Here is the translation of the Java code to Python:
```
import logging

class MetaGroupMember:
    def __init__(self):
        super().__init__()
        self.all_nodes = PartitionGroup()
        this_node = TestUtils.get_node(0)
        for i in range(10):
            self.all_nodes.add(TestUtils.get_node(i))
        log_manager = MetaSingleSnapshotLogManager(TestLogApplier(), self)
        set_log_manager(log_manager)

class TestMetaGroupMember(MetaGroupMember):
    pass

# Note: The following classes are not provided, so I couldn't translate them:
PartitionGroup
TestUtils
MetaSingleSnapshotLogManager
TestLogApplier
set_log_manager
```
Note that in Python, we don't need to specify the type of a variable (e.g. `int` or `String`) like we do in Java. Also, Python uses indentation to denote block-level structure, rather than curly braces.

Additionally, I didn't translate the following classes because they were not provided:

* PartitionGroup
* TestUtils
* MetaSingleSnapshotLogManager
* TestLogApplier
* set_log_manager

These classes would need to be implemented separately in order for this code to work.