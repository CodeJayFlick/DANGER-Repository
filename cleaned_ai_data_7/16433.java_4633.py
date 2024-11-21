class ConfigInconsistentException(Exception):
    def __init__(self):
        super().__init__("The configuration of this node is inconsistent with the cluster. See previous logs for explanation")
