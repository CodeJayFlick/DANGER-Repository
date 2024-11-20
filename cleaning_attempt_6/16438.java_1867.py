class LeaderUnknownException(Exception):
    def __init__(self, nodes):
        super().__init__("The leader is unknown in this group " + str(nodes))
