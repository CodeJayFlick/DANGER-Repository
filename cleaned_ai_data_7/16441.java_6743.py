class NoHeaderNodeException(Exception):
    def __init__(self):
        super().__init__("Header Node is required in data group communication!")
