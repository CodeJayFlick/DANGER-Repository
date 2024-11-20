import tkinter as tk
from tkinter import ttk
from typing import List, Set

class VTRelatedMatchesTableProvider:
    def __init__(self):
        self.controller = None  # VTController instance
        self.component = None  # JComponent instance
        self.table_panel = None  # MarkupItemThreadedTablePanel instance
        self.related_matches_table = None  # GhidraTable instance
        self.match_selection_listener = None  # ListSelectionListener instance
        self.related_matches_model_table = None  # RowObjectTableModel instance
        self.markup_filter_panel = None  # GhidraTableFilterPanel instance
        self.related_match_listeners: Set[any] = set()

    def create_component(self) -> tk.Frame:
        related_matches_table = self.create_related_match_table()
        markup_filter_panel = self.get_markup_filter_panel(related_matches_table, self.related_matches_model_table)
        table_panel = tk.Frame(parent=tk.Tk())
        table_panel.pack(side='top')
        table_panel.add_widgets(table=related_matches_table, filter_panel=markup_filter_panel)

    def create_related_match_table(self) -> ttk.Treeview:
        related_matches_model_table = RowObjectTableModel(VTRelatedMatch)
        self.related_matches_model_table = related_matches_model_table
        table_panel = MarkupItemThreadedTablePanel(related_matches_model_table)
        self.table_panel = table_panel

        # Add ListSelectionListener to the treeview
        for i in range(len(table_panel.get_children())):
            item = table_panel.get_children()[i]
            if isinstance(item, tk.TreeNode):
                related_match = VTRelatedMatch()
                related_matches_model_table.set_row_object(i, related_match)
                # Add ListSelectionListener to the treeview
        return self.table_panel

    def create_actions(self) -> None:
        pass  # addLocalAction and ignoreMarkupItemAction methods are not implemented in Python

    def notify_context_changed(self):
        if hasattr(self.controller, 'contextChanged'):
            self.controller.contextChanged(self)

    @property
    def action_context(self) -> any:
        return None  # getActionContext method is not implemented in Python

    def refresh(self) -> None:
        self.related_matches_model_table.reload()

    @property
    def component_(self):
        return self.component

    def dispose(self) -> None:
        if hasattr(self, 'related_matches_model_table'):
            self.related_matches_model_table.dispose()
        if hasattr(self, 'markup_filter_panel'):
            self.markup_filter_panel.dispose()
        # Remove from tool and remove listeners
        pass  # removeFromTool method is not implemented in Python

    def add_related_match_selection_listener(self, listener: any) -> None:
        self.related_match_listeners.add(listener)

    @property
    def related_matches_table_(self):
        return self.related_matches_table_

    def fire_related_match_selected(self, related_match: VTRelatedMatch) -> None:
        for listener in self.related_match_listeners:
            if hasattr(listener, 'relatedMatchSelected'):
                listener.relatedMatchSelected(related_match)

    @property
    def component_shown_(self):
        return True  # componentShown method is not implemented in Python

    def reload(self) -> None:
        pass  # reload method is not implemented in Python


class MarkupItemThreadedTablePanel(ttk.Treeview):
    def __init__(self, model: RowObjectTableModel[VTRelatedMatch]):
        super().__init__()
        self.model = model
