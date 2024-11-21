class Ext4File:
    def __init__(self, name: str, inode):
        self.name = name
        self.inode = inode

    @property
    def name(self) -> str:
        return self._name

    @property
    def inode(self) -> object:
        return self._inode


# Example usage:
if __name__ == "__main__":
    ext4_file = Ext4File("example.ext4", {"some": "data"})
    print(ext4_file.name)
    print(ext4_file.inode)
