Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the Python types and classes, as there is no direct equivalent in Java. For example:

* In Java, `BookmarkRowObject` has a getter for its key, but in Python, we can simply define an attribute `key` on the class.
* Similarly, `ProgramLocation` has constructors that take two arguments (program data and address), which I translated to attributes on the class.

You will need to implement the missing methods (`get_bookmark_manager()` on `BookmarkManager`, `get_bookmark()` on `BookmarkRowObject`, etc.) in order for this code to work.