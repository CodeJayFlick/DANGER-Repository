import tkinter as tk
from tkinter import messagebox

class CategoryMergePanel:
    def __init__(self):
        self.merge_manager = None
        self.total_conflicts = 0
        self.count_panel = None
        self.resolve_panel = None
        self.selected_option = None

    def set_merge_manager(self, merge_manager, total_conflicts):
        self.merge_manager = merge_manager
        self.total_conflicts = total_conflicts
        self.create()

    def create(self):
        self.count_panel = tk.Frame()
        self.resolve_panel = ResolvePanel("Resolve Conflict")
        self.use_for_all_cb = None

        root = tk.Tk()
        frame = tk.Frame(root)
        frame.pack(side=tk.TOP)

        count_label = tk.Label(frame, text="Conflict Count: 0/8")
        count_label.pack()

        resolve_frame = tk.Frame(frame)
        resolve_frame.pack()

        self.resolve_panel.pack_in(resolve_frame)

        use_for_all_frame = tk.Frame(frame)
        use_for_all_frame.pack()

        self.use_for_all_cb = tk.Checkbutton(use_for_all_frame, text="Use the selected option for resolving all remaining conflicts.")
        self.use_for_all_cb.pack(side=tk.LEFT)

    def set_conflict_info(self, conflict_index, latest_path, path, orig_path,
                           latest_renamed, renamed, latest_deleted, deleted):
        if (latest_renamed or renamed) and not deleted:
            s1 = "Use '" + latest_path + "' (" + MergeConstants.LATEST_TITLE + ")"
            s2 = "Use '" + path + "' (" + MergeConstants.MY_TITLE + ")"
            s3 = "Use '" + orig_path + "' (" + MergeConstants.ORIGINAL_TITLE + ")"
        elif (latest_deleted or deleted):
            if latest_deleted:
                s1 = "Delete '" + orig_path + "' (" + MergeConstants.LATEST_TITLE + ")"
                s2 = "Keep Category '" + path + "' (Checked Out)"
            else:
                s1 = "Keep Category '" + latest_path + "' (" + MergeConstants.LATEST_TITLE + ")"
                s2 = "Delete Category '" + orig_path + "' (" + MergeConstants.MY_TITLE + ")"

        self.resolve_panel.set_conflict_info(orig_path, s1, s2, s3)

    def get_selected_option(self):
        return self.resolve_panel.get_selected_option()

class ResolvePanel:
    def __init__(self, title):
        self.title = title
        self.conflict_info = None

    def set_conflict_info(self, orig_path, s1, s2, s3):
        pass  # Implement this method in your subclass.

    def get_selected_option(self):
        return 0  # Return the selected option. You may need to implement a GUI for this.

class ConflictCountPanel:
    def __init__(self):
        self.conflict_count = 0

    def update_count(self, conflict_index, total_conflicts):
        pass  # Implement this method in your subclass.

if __name__ == "__main__":
    root = tk.Tk()
    frame = tk.Frame(root)
    frame.pack(side=tk.TOP)

    p = CategoryMergePanel()

    p.set_merge_manager(None, 8)
    p.set_conflict_info(3, "/Category1/Category2/Category3/My Category",
                        "/Category1/Category2/Category3/Another Category",
                        "/Category1/Category2/Category3/Category4", True, True, False, False, False, False)

    frame.pack()
    root.mainloop()

class GCheckBox:
    def __init__(self):
        pass  # Implement this method in your subclass.

def get_use_all_string(conflict_type):
    return "Use the selected option for resolving all remaining '" + conflict_type + "' conflicts."
