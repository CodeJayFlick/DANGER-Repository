class GFile:
    def __init__(self):
        pass

    @property
    def filesystem(self):
        # Implement this method in your subclass to return the owning filesystem.
        raise NotImplementedError("filesystem not implemented")

    @property
    def fsrl(self):
        # Implement this method in your subclass to return the FSRL of this file.
        raise NotImplementedError("fsrl not implemented")

    @property
    def parent_file(self):
        # Implement this method in your subclass to return the parent directory of this file.
        raise NotImplementedError("parent_file not implemented")

    @property
    def path(self):
        # Implement this method in your subclass to return the path and filename of this file, relative to its owning filesystem.
        raise NotImplementedError("path not implemented")

    @property
    def name(self):
        # Implement this method in your subclass to return the name of this file.
        raise NotImplementedError("name not implemented")

    def is_directory(self):
        # Implement this method in your subclass to check if this file is a directory. Default returns False.
        return False

    def get_length(self):
        # Implement this method in your subclass to return the length of this file, or -1 if not known. Default returns -1.
        return -1

    @property
    def last_modified(self):
        # Implement this method in your subclass to return the last modified time of this file. Default returns -1.
        return -1

    def get_listing(self):
        # This is a default implementation that calls the filesystem's listing method with this GFile as an argument.
        raise NotImplementedError("get_listing not implemented")
