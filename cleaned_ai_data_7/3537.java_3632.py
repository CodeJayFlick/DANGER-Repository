import tkinter as tk
from tkinter import ttk
from typing import Dict

class CommentHistoryDialog:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Show Comment History")
        self.help_location = HelpLocation(HelpTopics.COMMENTS, "Show_Comment_History")

    def show_dialog(self, cu: CodeUnit, comment_type: int, tool: PluginTool, context: ActionContext) -> None:
        self.code_unit = cu
        self.program = cu.get_program()
        panel = self.get_history_panel(comment_type)
        panel.show_comment_history(self.program, cu.min_address())
        tabbedpane.select(int_to_tab_index[comment_type])
        for i in range(len(int_to_tab_index)):
            if int_to_tab_index[i] == comment_type:
                break
        tabbedpane.add_change_listener(self)

    def state_changed(self) -> None:
        index = tabbedpane.get_selected_index()
        panel = self.get_history_panel(int_to_tab_index[index])
        panel.show_comment_history(self.program, cu.min_address())

    def build_main_panel(self) -> tk.Frame:
        mainpanel = tk.Frame(self.root)
        tabbedpane = ttk.Notebook(mainpanel)

        eolpanel = CommentHistoryPanel(CodeUnit.EOL_COMMENT)
        prepanel = CommentHistoryPanel(CodeUnit.PRE_COMMENT)
        postpanel = CommentHistoryPanel(CodeUnit.POST_COMMENT)
        platepanel = CommentHistoryPanel(CodeUnit.PLATE_COMMENT)
        repeatablepanel = CommentHistoryPanel(CodeUnit.REPEATABLE_COMMENT)

        tabbedpane.add(ttk.Frame(mainpanel), text="EOL Comment")
        tabbedpane.add(ttk.Frame(mainpanel), text="Pre Comment")
        tabbedpane.add(ttk.Frame(mainpanel), text="Post Comment")
        tabbedpane.add(ttk.Frame(mainpanel), text="Plate Comment")
        tabbedpane.add(ttk.Frame(mainpanel), text="Repeatable Comment")

        mainpanel.pack()
        return mainpanel

    def get_history_panel(self, comment_type: int) -> tk.Frame:
        if comment_type == CodeUnit.EOL_COMMENT:
            return eolpanel
        elif comment_type == CodeUnit.PRE_COMMENT:
            return prepanel
        elif comment_type == CodeUnit.POST_COMMENT:
            return postpanel
        elif comment_type == CodeUnit.PLATE_COMMENT:
            return platepanel
        elif comment_type == CodeUnit.REPEATABLE_COMMENT:
            return repeatablepanel

class HelpLocation:
    def __init__(self, topic: str, location: str) -> None:
        self.topic = topic
        self.location = location

int_to_tab_index = {
    CodeUnit.EOL_COMMENT: 0,
    CodeUnit.PRE_COMMENT: 1,
    CodeUnit.POST_COMMENT: 2,
    CodeUnit.PLATE_COMMENT: 3,
    CodeUnit.REPEATABLE_COMMENT: 4
}
