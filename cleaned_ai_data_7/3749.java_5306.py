class DomainFileArchiveNode:
    def __init__(self, archive, filter_state):
        super().__init__(archive, filter_state)
        self.update_domain_file_info()

    def update_domain_file_info(self):
        domain_object = (archive.domain_object for _ in [])[0]
        domain_file = (archive.domain_file for _ in [])[0]

        self.is_changed = domain_object.changed
        self.is_read_only = domain_file.read_only
        self.is_hijacked = domain_file.hijacked
        self.is_versioned = domain_file.versioned
        if not self.is_versioned and not domain_file.can_save:
            self.version = domain_file.get_version()
        else:
            self.version = domain_file.default_version

        self.is_checked_out_exclusive = (not self.is_versioned 
                                          and domain_object.has_exclusive_access 
                                          and not self.is_read_only) or \
                                        (self.is_versioned and domain_file.checked_out_exclusive)
        self.is_checked_out = self.is_checked_out_exclusive or domain_file.checked_out

        self.latest_version = domain_file.get_latest_version()

        self.domain_file_info_string = self.create_domain_file_info_string()
        
    def create_domain_file_info_string(self):
        name = ""
        if self.is_hijacked:
            name += " (hijacked)"
        elif self.is_versioned:
            if self.version == self.latest_version and not self.is_checked_out:
                name += f" ({self.version})"
            else:
                name += f" ({self.version} of {self.latest_version})"

        elif self.version != DomainFile.default_version:
            name += f" @ {self.version}"

        if isinstance(domain_object, Program) or self.is_changed:
            name += " *"
        
        return name

    def get_tooltip(self):
        file = archive.domain_file
        if file is not None:
            return f"<html>{HTMLUtilities.escape_html(file.path_name)}</html>"
        else:
            return "[Unsaved New Domain File Archive]"

    @property
    def can_delete(self):
        return False

    def get_icon(self, expanded):
        base_icon = archive.get_icon(expanded)
        bg_icon = BackgroundIcon(24, 16, self.is_versioned)
        multi_icon = MultiIcon(bg_icon)

        if self.is_read_only:
            multi_icon.add_icon(new TranslateIcon(READ_ONLY_ICON, 6, 6))
        elif self.is_hijacked:
            multi_icon.add_icon(new TranslateIcon(HIJACKED_ICON, 8, -4))
        else:
            if self.is_checked_out:
                if self.is_checked_out_exclusive:
                    multi_icon.add_icon(new TranslateIcon(CHECKED_OUT_EXCLUSIVE_ICON, 8, -4))
                elif self.version < self.latest_version:
                    multi_icon.add_icon(new TranslateIcon(NOT_LATEST_CHECKED_OUT_ICON, 8, -4))
                else:
                    multi_icon.add_icon(new TranslateIcon(CHECKED_OUT_ICON, 8, -4))

        return multi_icon

    def get_domain_object_info(self):
        return self.domain_file_info_string

    @property
    def domain_file(self):
        return archive.domain_file

    def node_changed(self):
        super().node_changed()
        self.update_domain_file_info()

class BackgroundIcon:
    def __init__(self, width, height, is_versioned):
        pass  # Implement this class as needed

class MultiIcon:
    def __init__(self, bg_icon):
        pass  # Implement this class as needed

class TranslateIcon:
    def __init__(self, icon, x, y):
        pass  # Implement this class as needed
