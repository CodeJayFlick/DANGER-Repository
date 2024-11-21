class NotInSameGroupException(Exception):
    def __init__(self, group, node):
        super().__init__(f"This node {node} is not in the data group {group}")
