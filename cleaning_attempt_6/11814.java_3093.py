class BookmarkTypeDBAdapterNoTable:
    def __init__(self):
        self.records = []

    def set_old_bookmark_manager(self, old_mgr):
        self.records = old_mgr.get_type_records()

    def get_records(self):
        return self.records

# Example usage of the class
if __name__ == "__main__":
    db_handle = None  # Replace with your actual database handle
    old_mgr = OldBookmarkManager()  # Replace with your actual bookmark manager
    
    adapter = BookmarkTypeDBAdapterNoTable()
    adapter.set_old_bookmark_manager(old_mgr)
    
    try:
        records = adapter.get_records()
        for record in records:
            print(record)  # Do something with the record
    except Exception as e:
        print(f"An error occurred: {e}")
