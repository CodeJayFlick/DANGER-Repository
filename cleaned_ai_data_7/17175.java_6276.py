class PathGrouperByStorageGroup:
    def __init__(self, start_node, path):
        self.result_set = {}
        super().__init__(start_node, path)

    def process_internal_matched_mnode(self, node, idx, level):
        if node.is_storage_group():
            self.transfer_to_result(node, idx)
            return True
        return False

    def process_full_matched_mnode(self, node, idx, level):
        if node.is_storage_group():
            self.transfer_to_result(node, idx)
            return True
        return False

    def transfer_to_result(self, node, idx):
        sg_name = node.get_full_path()
        path_with_known_sg = sg_name + ""
        for i in range(idx+1, len(self.nodes)):
            path_with_known_sg += IoTDBConstant.PATH_SEPARATOR + self.nodes[i]
        if idx >= len(self.nodes) - 1 and self.nodes[-1] == IoTDBConstant.MULTI_LEVEL_PATH_WILDCARD:
            path_with_known_sg += IoTDBConstant.PATH_SEPARATOR + IoTDBConstant.MULTI_LEVEL_PATH_WILDCARD
        self.result_set[sg_name] = path_with_known_sg

    def get_result(self):
        return self.result_set


# Usage example:

class IMNode:
    def is_storage_group(self):
        pass  # implement this method according to your needs

class PartialPath:
    pass  # implement this class according to your needs

IoTDBConstant = {
    'PATH_SEPARATOR': '/',
    'MULTI_LEVEL_PATH_WILDCARD': '**'
}

start_node = IMNode()
path = PartialPath()

pgbsg = PathGrouperByStorageGroup(start_node, path)
# call the methods as needed
print(pgbsg.get_result())
