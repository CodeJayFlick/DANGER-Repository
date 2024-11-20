Here is the translation of the Java code into Python:

```Python
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

class OpenVersionedFileDialog:
    SHOW_HISTORY_PREFERENCES_KEY = "OPEN_PROGRAM_DIALOG.SHOW_HISTORY"
    HEIGHT_PREFERENCES_KEY = "OPEN_PROGRAM_DIALOG.HEIGHT"
    WIDTH_NO_HISTORY_PREFERENCES_KEY = "OPEN_PROGRAM_DIALOG.WIDTH_NO_HISTORY"
    WIDTH_WITH_HISTORY_PREFERENCES_KEY = "OPEN_PROGRAM_DIALOG.WIDTH_WITH_HISTORY"

    DEFAULT_WIDTH_NO_HISTORY = 200
    DEFAULT_WIDTH_WITH_HISTORY = 800

    DIVIDER_SIZE = 2

    def __init__(self, tool, title, filter):
        self.tool = tool
        self.title = title
        self.filter = filter
        self.historyIsShowing = False
        self.mainPanel = None
        self.splitPane = None
        self.historyButton = None
        self.popupActions = []
        self.init()

    def get_versioned_domain_object(self, consumer, read_only):
        if self.historyPanel is not None:
            return self.historyPanel.get_selected_version(consumer, read_only)
        else:
            return None

    def get_version(self):
        if self.historyPanel is not None:
            return self.historyPanel.get_selected_version_number()
        else:
            return -1

    def build_main_panel(self):
        mainPanel = super().build_main_panel()
        mainPanel.minimum_size = (200, 400)

        splitPane = tk.Splitter(orient=tk.HORIZONTAL)
        splitPane.pack(side=tk.LEFT, fill="both", expand=True)

        self.mainPanel = mainPanel
        self.splitPane = splitPane

    def advanced_button_callback(self):
        if not self.historyIsShowing:
            show_history_panel(True)
        else:
            show_history_panel(False)

    def show_history_panel(self, show_history):
        self.historyIsShowing = show_history
        if show_history:
            create_history_panel()
            self.historyButton.config(text="No History")
            df = treePanel.get_selected_domain_file()
            historyPanel.set_domain_file(df)
            splitPane.pack(fill="both", expand=True)

    def get_preferred_size_for_history_state(self):
        height = int(Preferences.get("HEIGHT"))
        key = "WIDTH_" + ("WITH_HISTORY" if self.historyIsShowing else "NO_HISTORY")
        default_width = (DEFAULT_WIDTH_WITH_HISTORY if self.historyIsShowing
                         else DEFAULT_WIDTH_NO_HISTORY)
        width = int(Preferences.get(key, str(default_width)))
        return tk.Size(width, height)

    def save_preferences(self):
        size = rootPanel.size()
        key = "WIDTH_" + ("WITH_HISTORY" if self.historyIsShowing else "NO_HISTORY")
        Preferences.set(key, str(size.width))
        Preferences.set("HEIGHT", str(size.height))

    def close(self):
        super().close()
        save_preferences()

    @staticmethod
    def dialog_shown():
        for action in popupActions:
            add_action(action)

    @staticmethod
    def dialog_closed():
        for action in popupActions:
            remove_action(action)

    def create_history_panel(self):
        try:
            historyPanel = VersionHistoryPanel(self.tool, None)
            self.popupActions = historyPanel.create_popup_actions()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return False

        historyPanel.border = tk.TitledBorder("Version History")
        splitPane.add_right(historyPanel)

    def init(self):
        self.historyButton = tk.Button(text="History>>", command=self.advanced_button_callback)
        add_button(self.historyButton)

        okButton.set_tooltip_text("Open the selected file")

        rootPanel.preferred_size = get_preferred_size_for_history_state()

    @staticmethod
    def add_tree_listeners():
        super().add_tree_listeners()
        treePanel.add_tree_selection_listener(lambda e: None)
```

Note that this translation is not a direct conversion from Java to Python, but rather an adaptation of the code into Python. The original code was written in Java and uses various libraries such as Swing for GUI components and Preferences for storing settings. In Python, we use tkinter (Tkinter) for creating GUI components and `filedialog` for file operations.

The translation also includes some simplifications to make it more readable and maintainable.