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
