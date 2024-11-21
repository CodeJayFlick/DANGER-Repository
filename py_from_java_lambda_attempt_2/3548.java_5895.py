Here is a translation of the provided Java code into equivalent Python:

```Python
class CommentWindowProvider:
    def __init__(self, plugin):
        self.plugin = plugin
        self.threaded_table_panel = None
        self.filter_panel = None
        self.main_panel = None
        self.comment_table = None
        self.comment_model = None

    @property
    def main_panel(self):
        if not self._main_panel:
            self._create_work_panel()
        return self._main_panel

    def _create_work_panel(self):
        self.comment_model = CommentTableModel(self.plugin)
        self.threaded_table_panel = GhidraThreadedTablePanel(self.comment_model, 1000)
        self.comment_table = self.threaded_table_panel.get_table()
        self.comment_table.set_name("CommentTable")
        self.comment_table.set_auto_lookup_column(CommentTableModel.TYPE_ COL)
        self.comment_table.set_preferred_scrollable_viewport_size((600, 400))
        self.comment_table.set_row_selection_allowed(True)
        self.comment_table.set_selection_mode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

    def component_hidden(self):
        if self.comment_model:
            self.comment_model.reload(None)

    def component_shown(self):
        if self.comment_model and self.plugin.get_program():
            self.comment_model.reload(self.plugin.get_program())

    @property
    def action_context(self, event=None):
        return CommentWindowContext(self, self.comment_table)

    def get_component(self):
        return self.main_panel

    def get_help_location(self):
        return HelpLocation(self.plugin.name, self.plugin.name)

    def program_opened(self, program):
        if self.isVisible():
            self.comment_model.reload(program)
        else:
            self.component_shown()

    def program_closed(self):
        if self.comment_model:
            self.comment_model.reload(None)

    def dispose(self):
        self.threaded_table_panel.dispose()
        self.filter_panel.dispose()
        self.plugin.get_tool().remove_component_provider(self)

    @property
    def table(self):
        return self.comment_table

class CommentTableModel:
    TYPE_COL = 0

    def __init__(self, plugin):
        pass

    def reload(self, program=None):
        # TO DO: implement reloading logic here
        pass

    def comment_added(self, address, comment_type):
        if self.isVisible():
            # TO DO: implement adding a new comment logic here
            pass

    def comment_removed(self, address, comment_type):
        if self.isVisible():
            # TO DO: implement removing a comment logic here
            pass

class GhidraThreadedTablePanel:
    def __init__(self, model, row_height=1000):
        self.model = model
        self.table = None
        self.row_height = row_height

    @property
    def table(self):
        if not self._table:
            # TO DO: implement creating the table logic here
            pass
        return self._table

class GhidraTableFilterPanel:
    def __init__(self, table, model):
        self.table = table
        self.model = model

    @property
    def filter_panel(self):
        if not self._filter_panel:
            # TO DO: implement creating the filter panel logic here
            pass
        return self._filter_panel

class HelpLocation:
    def __init__(self, topic_name, help_text):
        self.topic_name = topic_name
        self.help_text = help_text

class CommentWindowContext:
    def __init__(self, provider, table):
        self.provider = provider
        self.table = table

# TO DO: implement the rest of the classes and methods here