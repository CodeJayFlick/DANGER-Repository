import os
from threading import Thread

class LocalFileChooserModel:
    PROBLEM_FILE_ICON = "unknown.gif"

    def __init__(self):
        self.fs_view = FileSystemView()
        self.root_descrip_map = {}
        self.root_icon_map = {}
        self.roots = []
        self.listener = None

    def get_separator(self):
        return os.sep

    def set_listener(self, listener):
        self.listener = listener

    def get_home_directory(self):
        return os.path.expanduser("~")

    def get_desktop_directory(self):
        user_home_prop = os.environ.get("USERPROFILE")
        if not user_home_prop:
            return None
        home_dir = os.path.join(user_home_prop, "Desktop")
        return os.path.exists(home_dir) and os.path.isdir(home_dir)

    def get_roots(self):
        if len(self.roots) == 0:
            self.roots = [os.path.normpath(root) for root in os.listdir("/")]
            # pre-populate root Description cache mapping with placeholder values that will be overwritten by the background thread. 
            for r in self.roots:
                self.root_descrip_map[r] = get_fast_root_description_string(r)
                self.root_icon_map[r] = self.fs_view.get_system_icon(r)

            Thread(target=self.background_file_scan_thread).start()
        return self.roots

    def get_fast_root_description_string(self, root):
        fsv_std = "Unknown status"
        try:
            fsv_std = self.fs_view.get_system_type_description(root)
        except Exception as e:
            #Windows expects the A drive to exist; if it does not exist, an exception results.  Ignore it
            pass

        return "{} ({})".format(fsv_std, format_root_path_for_display(root))

    def get_root_description_string(self, root):
        if "/" == os.path.abspath(root):
            return "File system root (/)"
        elif self.fs_view.is_floppy_drive(root):
            return f"Floppy ({os.path.abspath(root)})"
        else:
            try:
                return self.fs_view.get_system_type_description(root)
            except Exception as e:
                # ignore, fall thru
                pass

    def format_root_path_for_display(self, root):
        s = os.path.abspath(root)
        if len(s) > 1 and s.endswith("\\"):
            return s[:len(s)-1]
        else:
            return s

    def get_listing(self, directory, filter):
        if not directory:
            return []
        files = [os.path.join(directory, f) for f in os.listdir(directory) if filter(f)]
        return files

    def get_icon(self, file):
        if self.root_icon_map.get(file):
            return self.root_icon_map[file]
        elif file and file.exists():
            try:
                return self.fs_view.get_system_icon(file)
            except Exception as e:
                # ignore, fall thru
                pass
        else:
            return PROBLEM_FILE_ICON

    def get_description(self, file):
        if self.root_descrip_map.get(file):
            return self.root_descrip_map[file]
        else:
            try:
                return self.fs_view.get_system_type_description(file)
            except Exception as e:
                # ignore, fall thru
                pass

    def create_directory(self, directory, name):
        new_dir = os.path.join(directory, name)
        return os.mkdir(new_dir)

    def is_directory(self, file):
        for root in self.roots:
            if root == file:
                return True
        return file and file.is_directory()

    def is_absolute(self, file):
        return file and file.isabs()

    def rename_file(self, src, dest):
        for root in self.roots:
            if root == src:
                return False
        return os.rename(src, dest)

    def background_file_scan_thread(self):
        for r in self.roots:
            self.root_descrip_map[r] = get_root_description_string(r)
        if self.listener:
            self.listener.model_changed()

def main():
    model = LocalFileChooserModel()
    # Use the model here

if __name__ == "__main__":
    main()
