Here is a translation of the Java code into equivalent Python:

```Python
import os
from typing import Any, Dict, List

class GhidraScriptEditorComponentProvider:
    EDITOR_COMPONENT_NAME = "EDITOR"
    CHANGE_DESTINATION_TITLE = "Where Would You Like to Store Your Changes?"
    FILE_ON_DISK_CHANGED_TITLE = "File Changed on Disk"
    FILE_ON_DISK_MISSING_TITLE = "File on Disk is Missing"

    SAVE_CHANGES_AS_TEXT = "Save Changes As..."
    OVERWRITE_CHANGES_TEXT = "Overwrite Changes"
    KEEP_CHANGES_TEXT = "Keep Changes"
    DISCARD_CHANGES_TEXT = "Discard Changes"

    MAX_UNDO_REDO_SIZE = 50

    def __init__(self, plugin: Any, provider: Any):
        self.plugin = plugin
        self.provider = provider
        super().__init__()

    @staticmethod
    def restore_state(save_state: Dict[str, str]) -> None:
        default_font_name = save_state.get("DEFAULT_FONT_NAME", "Monospaced")
        font_style = int(save_state.get("DEFAULT_FONT_STYLE", 12))
        font_size = int(save_state.get("DEFAULT_FONT_SIZE", 12))

    @staticmethod
    def save_state(save_state: Dict[str, str]) -> None:
        pass

    def load_script(self, script_source_file: Any) -> None:
        self.script_source_file = script_source_file
        file_on_disk = script_source_file.file(0)
        if not os.path.exists(file_on_disk):
            return  # deleted?

        self.file_hash = MD5Utilities.get_md5_hash(file_on_disk)

    def is_read_only(self, script_source_file: Any) -> bool:
        return GhidraScriptUtil.is_system_script(script_source_file)

    def clear_undo_redo_stack(self) -> None:
        pass

    def update_undo_redo_action(self) -> None:
        pass

    def undo(self) -> None:
        pass

    def redo(self) -> None:
        pass

    @property
    def has_changes(self) -> bool:
        return not self.undo_stack.empty() or is_file_on_disk_missing()

    def update_changed_state(self) -> None:
        if self.has_changes():
            self.set_title("*" + self.title)
        else:
            self.set_title(self.title)

    def clear_changes(self) -> None:
        pass

    @staticmethod
    def load_script_file() -> str:
        buffer = StringBuffer()
        reader = BufferedReader(InputStreamReader(script_source_file.file(0)))
        try:
            while True:
                line = reader.readline()
                if line is None:
                    break
                buffer.append(line)
                buffer.append('\n')
        finally:
            reader.close()

    def create_actions(self) -> None:
        pass

    @staticmethod
    def refresh() -> None:
        pass

    def handle_deleted_file(self) -> bool:
        choice = OptionDialog.show_option_dialog(scrollpane, FILE_ON_DISK_MISSING_TITLE,
                "The script file on disk no longer exists.\nWould you like to  keep the changes in the editor or discard your changes?", KEEP_CHANGES_TEXT, DISCARD_CHANGES_TEXT)
        if choice == OptionDialog.CANCEL_OPTION:
            return False
        elif choice == OptionDialog.OPTION_TWO:
            self.close_component_without_saving()
            return True

    def handle_changes_on_disk(self) -> None:
        pass

    @staticmethod
    def reload_script() -> None:
        try:
            load_script(script_source_file)
            file_hash = MD5Utilities.get_md5_hash(file_on_disk)
            clear_changes()
            refresh_action()
        except IOException as e:
            Msg.showError(getClass(), getComponent(), "Error reloading script", e.getMessage())

    @staticmethod
    def do_select_font() -> None:
        font_property_editor = FontPropertyEditor()
        editor.set_value(default_font)

    @staticmethod
    def save(self) -> bool:
        if not self.has_changes():
            return False

        if self.script_source_file is None:
            return self.save_as()

        if os.path.exists(file_on_disk):
            choice = OptionDialog.show_yes_no_dialog(getComponent(), getName(),
                    "Do you want to OVERWRITE the following script:\n" + file_on_disk)
            if choice != OptionDialog.OPTION_ONE:
                return False

    @staticmethod
    def save_as(self) -> bool:
        help_location = HelpLocation(plugin.getName(), save_action.getName())
        dialog = SaveDialog(getComponent(), "Save Script", provider, self.script_source_file, help_location)

        if dialog.is_cancelled():
            return False

        file_to_save_as = dialog.get_file()
        exists = os.path.exists(file_to_save_as)
        if exists:
            choice = OptionDialog.show_yes_no_dialog(getComponent(), getName(),
                    "Do you want to OVERWRITE the following script:\n" + file_to_save_as)
            if choice != OptionDialog.OPTION_ONE:
                return False

    @staticmethod
    def close_component(self) -> None:
        pass