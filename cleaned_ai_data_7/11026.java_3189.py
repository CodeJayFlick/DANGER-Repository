import datetime
from typing import Dict, Any

class DomainFileInfo:
    def __init__(self, domain_file: Any):
        self.domain_file = domain_file
        self.path = domain_file.parent.get_pathname()
        self.name = None
        self.modification_date = None
        self.domain_file_type = None
        self.metadata = {}

    def compute_name(self) -> str:
        display_name = self.domain_file.name

        if self.domain_file.is_hijacked():
            display_name += " (hijacked)"
        elif self.domain_file.is_versioned():
            version_number = self.domain_file.get_version()
            version_str = f"{version_number}"
            if version_number < 0:
                version_str = "?"
            if not self.domain_file.is_checked_out():
                latest_version_number = self.domain_file.get_latest_version()
                latest_version_str = f"{latest_version_number}"
                if latest_version_number <= 0:
                    latest_version_str = "?"
                display_name += f" ({version_str} of {latest_version_str})"
                if self.domain_file.modified_since_checkout():
                    display_name += "*"
            else:
                display_name += f" ({version_str})"

        return display_name

    @property
    def display_name(self) -> str:
        if not self.name:
            self.name = self.compute_name()
        return self.name

    @property
    def path_(self) -> str:
        if not self.path:
            self.path = self.domain_file.parent.get_pathname()
        return self.path

    def get_icon(self) -> Any:
        return self.domain_file.get_icon(False)

    @property
    def domain_file_type(self) -> 'DomainFileType':
        if not self.domain_file_type:
            content_type = self.domain_file.get_content_type()
            icon = self.domain_file.get_icon(False)
            is_versioned = self.domain_file.is_versioned()
            self.domain_file_type = DomainFileType(content_type, icon, is_versioned)
        return self.domain_file_type

    @property
    def modification_date(self) -> datetime.date:
        if not self.modification_date:
            self.modification_date = self.get_last_modified_time()
        return self.modification_date

    def get_last_modified_time(self) -> datetime.date:
        last_modified = self.domain_file.get_last_modified_time()
        if last_modified != 0:
            return datetime.datetime.fromtimestamp(last_modified).date
        return datetime.date.today()

    @property
    def metadata_(self) -> Dict[str, str]:
        if not self.metadata:
            self.metadata = self.domain_file.get_metadata() or {}
        return self.metadata

    def get_domain_file(self) -> Any:
        return self.domain_file

    def clear_meta_cache(self):
        self.modification_date = None
        self.domain_file_type = None
        self.refresh()

    def refresh(self):
        self.name = None
        self.path_ = None


class DomainFileType:
    def __init__(self, content_type: str, icon: Any, is_versioned: bool):
        self.content_type = content_type
        self.icon = icon
        self.is_versioned = is_versioned

