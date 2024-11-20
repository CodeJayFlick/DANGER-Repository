class DBFileListener:
    """Facilitates listener notification when new database versions are created."""
    
    def version_created(self, db: str, version: int):
        """A new database version has been created.
        
        Args:
            db (str): The name of the database.
            version (int): The number of the newly created version.
        """
