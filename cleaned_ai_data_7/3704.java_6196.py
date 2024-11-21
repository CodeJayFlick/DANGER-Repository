class ArchiveManagerListener:
    def __init__(self):
        pass

    def archive_opened(self, archive: 'Archive'):
        """Called when a new Archive is opened."""
        pass  # TO DO: implement this method

    def archive_closed(self, archive: 'Archive'):
        """Called when an archive is closed."""
        pass  # TO DO: implement this method

    def archive_state_changed(self, archive: 'Archive'):
        """Called when the edited state of the archive has changed, for example, when an archive
           has had a data type or category added or removed."""
        pass  # TO DO: implement this method

    def archive_data_type_manager_changed(self, archive: 'Archive'):
        """Called when the DataTypeManager of the archive has changed. This can happen when
           an archive is locked or unlocked."""
        pass  # TO DO: implement this method


class Archive:
    pass  # TO DO: define the Archive class

