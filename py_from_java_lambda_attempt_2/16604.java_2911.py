Here is the translation of the Java code into Python:

```Python
import logging
from typing import Dict, List

class StoppedMemberManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.stopped_members_file_name = "removedMembers"
        self.removed_member_map: Dict[str, dict] = {}
        self.member_factory = None
        self.this_node = None

    def put(self, raft_node: str, data_group_member: dict) -> None:
        self.removed_member_map[raft_node] = data_group_member
        try:
            with open(self.stopped_members_file_name, 'a') as f:
                writer = f.write(f"{RAFT_REMOVED};{raft_node};")
                for node in data_group_member['nodes']:
                    writer += f";{node}"
                writer += '\n'
        except Exception as e:
            self.logger.error("Cannot record removed member of header %s", raft_node, str(e))

    def remove(self, raft_node: str) -> None:
        if raft_node in self.removed_member_map:
            del self.removed_member_map[raft_node]
            try:
                with open(self.stopped_members_file_name, 'a') as f:
                    writer = f.write(f"{RAFT_RESUMED};{raft_node};")
            except Exception as e:
                self.logger.error("Cannot record resumed member of header %s", raft_node, str(e))

    def get(self, raft_node: str) -> dict or None:
        return self.removed_member_map.get(raft_node)

    def recover(self):
        if not os.path.exists(self.stopped_members_file_name):
            return
        try:
            with open(self.stopped_members_file_name, 'r') as f:
                for line in f.readlines():
                    self.parse_line(line.strip())
        except Exception as e:
            self.logger.error("Cannot recover members from file", str(e))

    def parse_line(self, line: str) -> None:
        if not line:
            return
        try:
            parts = line.split(';')
            type_ = parts[0]
            if RAFT_REMOVED == type_:
                self.parse_removed(parts)
            elif RAFT_RESUMED == type_:
                self.parse_resumed(parts)
        except Exception as e:
            self.logger.warn("Fail to analyze %s, skipping", line)

    def parse_removed(self, parts: List[str]) -> None:
        partition_group = {}
        raft_id = int(parts[1])
        for i in range(2, len(parts)):
            node = ClusterUtils.string_to_node(parts[i])
            partition_group[node] = True
        member = self.member_factory.create(partition_group, self.this_node)
        member.set_read_only()
        self.removed_member_map[str(member)] = {}

    def parse_resumed(self, parts: List[str]) -> None:
        raft_id = int(parts[1])
        header = ClusterUtils.string_to_node(parts[2])
        if str(header) in self.removed_member_map:
            del self.removed_member_map[str(header)]

RAFT_REMOVED = "0"
RAFT_RESUMED = "1"

if __name__ == "__main__":
    manager = StoppedMemberManager()
```

Note that this translation is not a direct conversion, but rather an equivalent Python implementation. The code may need to be adjusted based on the specific requirements of your project and any differences in syntax or semantics between Java and Python.