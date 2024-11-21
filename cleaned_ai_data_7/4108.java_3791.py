class BundleStatusTableModel:
    def __init__(self, provider: 'BundleStatusComponentProvider', bundle_host: 'BundleHost'):
        self.provider = provider
        self.bundle_host = bundle_host
        self.statuses = []
        for bundle in bundle_host.get_ghidra_bundles():
            self.add_new_status(bundle)

        self.bundle_host_listener = MyBundleHostListener()
        self.bundle_host.add_listener(self.bundle_host_listener)

    def add_new_status_no_fire(self, bundle: 'GhidraBundle'):
        status = BundleStatus(bundle.file, bundle.is_enabled(), bundle.is_system_bundle(),
                               bundle.location_identifier)
        if not status.read_only:
            self.statuses.append(status)
            self.bundle_loc_to_status_map[status.location_identifier] = status

    def add_new_status(self, bundle: 'GhidraBundle'):
        SwingUtilities.invokeLater(lambda: (self.add_new_status_no_fire(bundle),
                                               self.fire_table_rows_inserted(len(self.statuses), len(self.statuses))))

    @staticmethod
    def get_row_object(row_index):
        return self.statuses[row_index]

    def remove_status_no_fire(self, status: 'BundleStatus'):
        if not status.read_only:
            index = self.statuses.index(status)
            self.statuses.remove(index)
            del self.bundle_loc_to_status_map[status.location_identifier]
            return index

    def remove_status(self, status: 'BundleStatus'):
        SwingUtilities.invokeLater(lambda: (self.remove_status_no_fire(status),
                                               self.fire_table_rows_deleted(len(self.statuses), len(self.statuses))))

    @staticmethod
    def get_column_name(column_index):
        # This is a placeholder for the actual column name.
        return f"Column {column_index}"

class MyBundleHostListener:
    def bundle_built(self, bundle: 'GhidraBundle', summary: str):
        SwingUtilities.invokeLater(lambda: (self.bundle_status.set_summary(summary),
                                               self.fire_table_rows_updated(len(self.statuses), len(self.statuses))))

    # ... other methods

class BundleStatusColumn(Column[str]):
    def __init__(self):
        super().__init__("OSGi State")

    @staticmethod
    def get_value(status, settings, data, serviceProvider0) -> str:
        if not status.is_enabled():
            return "(DISABLED)"
        ghidra_bundle = self.bundle_host.get_ghidra_bundle(status.file)
        if ghidra_bundle is None:
            return "(UNINSTALLED)"
        else:
            return OSGiUtils.get_state_string(ghidra_bundle)

    @staticmethod
    def get_column_preferred_width():
        return 100

class BundleTypeColumn(Column[str]):
    def __init__(self):
        super().__init__("Bundle Type")

    @staticmethod
    def get_value(status, settings, data, serviceProvider0) -> str:
        return status.type.toString()

    @staticmethod
    def get_column_preferred_width():
        return 90

class EnabledColumn(Column[bool]):
    def __init__(self):
        super().__init__("Enabled")

    @staticmethod
    def get_value(status: 'BundleStatus', settings, data, serviceProvider0) -> bool:
        return status.is_enabled()

    @staticmethod
    def is_editable(status: 'BundleStatus') -> bool:
        return status.file_exists()

    @staticmethod
    def set_value(status: 'BundleStatus', new_value: bool):
        BundleStatusTableModel.fire_bundle_enablement_change_requested(status, new_value)

class BundleFileColumn(Column[ResourceFile]):
    def __init__(self):
        super().__init__("Path")
        self.comparator = lambda a, b: Path.to_path_string(a).compareTo(Path.to_path_string(b))

    @staticmethod
    def get_value(status: 'BundleStatus', settings, data, serviceProvider0) -> ResourceFile:
        return status.file

    @staticmethod
    def get_column_renderer():
        # This is a placeholder for the actual column renderer.
        return BundleFileRenderer()

    @staticmethod
    def get_comparator():
        return self.comparator

class BundleFileRenderer(AbstractGColumnRenderer[ResourceFile]):
    @staticmethod
    def get_table_cell_renderer_component(data):
        status = data.row_object
        file = data.value
        label = super().get_table_cell_renderer_component(data)
        label.font = default_font.derive_font(default_font.style | Font.BOLD)
        label.text = Path.to_path_string(file)

        ghidra_bundle = self.bundle_host.get_ghidra_bundle(file)
        if ghidra_bundle is None or isinstance(ghidra_bundle, GhidraPlaceholderBundle) or not file.exists():
            label.foreground_color = COLOR_BUNDLE_ERROR
        elif status.is_busy:
            label.foreground_color = COLOR_BUNDLE_BUSY
        elif not status.is_enabled:
            label.foreground_color = COLOR_BUNDLE_DISABLED
        elif status.is_active:
            label.foreground_color = COLOR_BUNDLE_ACTIVE
        else:
            label.foreground_color = COLOR_BUNDLE_INACTIVE

        return label

    @staticmethod
    def get_filter_string(file, settings):
        # This is a placeholder for the actual filter string.
        return Path.to_path_string(file)
