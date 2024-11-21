class TraceBookmarkRegisterSpace:
    def get_thread(self):
        pass  # This method should be implemented in subclass

    def add_bookmark(self, lifespan: range, register_address: int, 
                     bookmark_type: str, category: str, comment: str) -> 'TraceBookmark':
        return self.add_bookmark(lifespan, register_address, bookmark_type, category, comment)

    def get_bookmarks_enclosed(self, lifespan: range, register_range: tuple[int]) -> iter:
        pass  # This method should be implemented in subclass

    def get_bookmarks_intersecting(self, lifespan: range, register_range: tuple[int]) -> iter:
        pass  # This method should be implemented in subclass
