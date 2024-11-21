class DomainFolderChangesDisplayPlugin:
    def __init__(self):
        pass

    def init(self):
        project_manager = tool.get_project_manager()
        active_project = project_manager.get_active_project()
        if active_project is not None:
            self.project_opened(active_project)
        
        front_end_service = tool.get_front_end_service()
        front_end_service.add_project_listener(self)

    def dispose(self):
        front_end_service = tool.get_front_end_service()
        front_end_service.remove_project_listener(self)

        project_manager = tool.get_project_manager()
        active_project = project_manager.get_active_project()
        if active_project is not None:
            self.project_closed(active_project)

    def project_opened(self, project):
        pass

    def project_closed(self, project):
        pass

    def domain_folder_added(self, folder):
        print(f"domainFolderAdded: {folder.path}")

    def domain_file_added(self, file):
        print(f"domainFileAdded: {file.path}")

    def domain_folder_removed(self, parent, name):
        print(f"domainFolderRemoved: parent={parent.path}, name={name}")

    def domain_file_removed(self, parent, name, file_id):
        print(f"domainFileRemoved: parent={parent.path}, name={name}, fileID={file_id}")

    def domain_folder_renamed(self, folder, old_name):
        print(f"domainFolderRenamed: {folder.path}, oldName={old_name}")

    def domain_file_renamed(self, file, old_name):
        print(f"domainFileRenamed: {file.path}, oldName={old_name}")

    def domain_folder_moved(self, folder, old_parent):
        print(f"domainFolderMoved: {folder.path}, oldParent={old_parent.path}")

    def domain_file_moved(self, file, old_parent, old_name):
        print(f"domainFileMoved: {file.path}, oldParent={old_parent.path}, oldName={old_name}")

    def domain_folder_set_active(self, folder):
        print(f"domainFolderSetActive: {folder.path}")
