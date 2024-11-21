class DomainFileIndex:
    def __init__(self, project_data):
        self.project_data = project_data
        self.file_id_to_path_index = {}

    def update_file_entry(self, df):
        if isinstance(df, GhidraFileData):
            return self.update_file_entry(df.get_domain_file(), df.get_file_id(), df.get_pathname())
        elif isinstance(df, GhidraFile):
            return self.update_file_entry(df, df.get_file_id(), df.get_pathname())

    def update_file_entry(self, df, file_id, path_name):
        if file_id is not None:
            old_path = self.file_id_to_path_index.get(file_id)
            if old_path is None:
                self.file_id_to_path_index[file_id] = path_name
            elif old_path == path_name:
                return
            else:
                old_df = self.project_data.get_file(old_path)
                if old_df is not None and (not old_df.is_checked_out() or not old_df.is_versioned()):
                    Msg.warn(self, f"WARNING! changing file-ID for {old_path}")
                    old_df.reset_file_id()
                new_df = self.project_data.get_file(path_name)
                if new_df is not None and (not new_df.is_checked_out() or not new_df.is_versioned()):
                    Msg.warn(self, f"WARNING! changing file-ID for {path_name}")
                    new_df.reset_file_id()

    def remove_file_entry(self, file_id):
        self.file_id_to_path_index.pop(file_id, None)

    def reconcile_file_id_conflict(self, df1, df2):
        try:
            path1 = df1.get_pathname()
            path2 = df2.get_pathname()
            if not df1.is_checked_out() and not df1.is_versioned():
                Msg.warn(self, f"WARNING! changing file-ID for {path1}")
                df1.reset_file_id()
            elif not df2.is_checked_out() and not df2.is_versioned():
                Msg.warn(self, f"WARNING! changing file-ID for {path2}")
                df2.reset_file_id()
            else:
                # Unable to resolve conflict
                Msg.error(self, "The following project files have conflicting file-IDs!\n" + path1 + "\n" + path2)
        except IOException as e:
            Msg.error(self, f"Error while resolving file IDs: {e}")
            e.print_stacktrace()

    def get_file_by_id(self, file_id):
        try:
            return self.project_data.get_file(self.file_id_to_path_index[file_id])
        except KeyError:
            pass

        for folder in self.project_data.get_root_folder().get_subfolders():
            if isinstance(folder, GhidraFolderData) and not folder.visited():
                folder.refresh(False, True)
                try:
                    return self.find_file_by_id(folder, file_id)
                except IOException as e:
                    Msg.error(self, f"File index lookup failed due to error: {e}")
        return None

    def find_file_by_id(self, folder_data, file_id):
        if not folder_data.visited():
            folder_data.refresh(False, True)

        for name in folder_data.get_folder_names():
            subfolder = folder_data.get_folder_data(name)
            if isinstance(subfolder, GhidraFolderData) and not subfolder.visited():
                try:
                    return self.find_file_by_id(subfolder, file_id)
                except IOException as e:
                    Msg.error(self, f"File index lookup failed due to error: {e}")
        # perform extra check to handle potential race condition
        if file_id in self.file_id_to_path_index:
            return self.project_data.get_file(self.file_id_to_path_index[file_id])
        return None

    def domain_file_added(self, file):
        self.update_file_entry(file)

    def domain_file_moved(self, file, old_parent, old_name):
        self.update_file_entry(file)

    def domain_file_removed(self, parent, name, file_id):
        self.file_id_to_path_index.pop(file_id, None)
