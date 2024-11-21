class BookmarkRowObjectToProgramLocationTableRowMapper:
    def map(self, row_object: 'BookmarkRowObject', program_data, service_provider):
        bookmark_manager = program_data.get_bookmark_manager()
        bookmark = bookmark_manager.get_bookmark(row_object.key)
        if bookmark is None:
            return None
        return ProgramLocation(program_data, bookmark.address)

class BookmarkManager:
    def get_bookmark(self, key):
        # implement me!

class BookmarkRowObject:
    def __init__(self, key):
        self.key = key

class ProgramData:
    def get_bookmark_manager(self):
        # implement me!

class ProgramLocation:
    def __init__(self, program_data: 'ProgramData', address):
        self.program_data = program_data
        self.address = address
