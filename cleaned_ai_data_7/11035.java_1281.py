import sys
from gi.repository import Gtk
from ghidra_framework_main_datatable import *
from ghidra_framework_model import *

class ProjectDataTablePanel(Gtk.Panel):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin
        self.tool = None
        self.project_data = None
        self.model = None
        self.capacity_exceeded = False
        self.files_pending_selection = set()
        
        # Initialize the table and other components
        
    def dispose(self):
        if self.table:
            self.table.dispose()

    def set_help_location(self, help_location):
        pass

    def selected_domain_files(self, files):
        if not self.model.is_busy():
            do_set_selected_domain_files(files)

    def do_set_selected_domain_files(self, files):
        row_list = []
        selected_row_objects = []
        for i in range(len(self.model.get_rows())):
            info = self.model.get_row_object(i)
            domain_file = info.get_domain_file()
            if files.contains(domain_file):
                row_list.append(i)
                selected_row_objects.append(info)

    def select_rows(self, row_list):
        selection_model = self.table.get_selection_model()
        selection_model.clear_selection()
        for i in row_list:
            selection_model.add_selection_interval(i, i)
        selection_model.set_value_is_adjusting(False)

    def set_project_data(self, name, project_data):
        if self.project_data is not None:
            self.project_data.remove_domain_folder_listener(self.change_listener)
            self.model.set_project_data(None)
        
        self.project_data = project_data
        self.capacity_exceeded = False

        if project_data is not None:
            check_capacity()
            if not capacity_exceeded:
                model.set_project_data(project_data)
                project_data.add_domain_folder_listener(self.change_listener)

    def clear_info(self, file):
        pass

    def reload(self):
        check_capacity()

    @staticmethod
    def load_max_file_count():
        property = sys.getProperty("ProjectDataTable.maxFileCount", str(ProjectDataTablePanel.MAX_FILE_COUNT_DEFAULT))
        
        try:
            return int(property)
        except ValueError:
            Msg.error(ProjectDataTablePanel, "Invalid ProjectDataTable.maxFileCount property value: {}".format(property))

class SelectPendingFilesListener(Gtk.TreeModelListner):
    def loading_finished(self, was_cancelled):
        if self.files_pending_selection is not None:
            do_set_selected_domain_files(self.files_pending_selection)
            self.files_pending_selection = None

    def load_pending(self):
        pass

    def loading_started(self):
        pass

class ProjectDataTable(Gtk.TreeView):
    def __init__(self, model):
        super().__init__()
        self.model = model
        self.set_model(model)

    def supports_popup_actions(self):
        return False

class TableGlassPanePainter:
    def paint(self, glass_pane, graphics):
        if not capacity_exceeded or not table.is_showing():
            return
        
        container = table.get_parent()
        bounds = container.get_bounds()

        preferred_size = capacity_exceeded_text.get_preferred_size()
        
        width = min(preferred_size.width, bounds.width)
        height = min(preferred_size.height, bounds.height)

        x = bounds.x + (bounds.width / 2 - width / 2)
        y = bounds.y + (bounds.height / 2 - height / 2)

        renderer.paint_component(graphics, capacity_exceeded_text, container, x, y, width, height)

class DateCellRenderer(Gtk.TreeViewColumn):
    def get_cell_renderer(self, data):
        label = Gtk.Label()
        
        value = data.get_value()

        if value is not None:
            label.set_text(DateUtils.format_date_timestamp(value))
        else:
            label.set_text("")

        return label

class TypeCellRenderer(Gtk.TreeViewColumn):
    def get_cell_renderer(self, data):
        label = Gtk.Label()
        
        value = data.get_value()

        label.set_text("")
        if value is not None:
            type = DomainFileType(value)
            set_tooltip_text(type.get_content_type())
            set_text("")
            set_icon(type.get_icon())

        return label

# Inner classes
class ProjectDataTableDomainFolderChangeListener(Gtk.DomainFolderListener):
    def domain_folder_added(self, folder):
        pass

    def domain_file_added(self, file):
        if capacity_exceeded:
            check_capacity()
            model.add_object(DomainFileInfo(file))

    def domain_folder_removed(self, parent, name):
        pass

    def domain_file_removed(self, parent, name, file_id):
        pass

    def domain_folder_renamed(self, folder, old_name):
        pass

    def domain_file_renamed(self, file, old_name):
        pass

    def domain_folder_moved(self, folder, old_parent):
        pass
