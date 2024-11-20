Here is the translation of the Java code into Python:

```Python
class VersionControlUndoHijackAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Undo Hijack", plugin.name, plugin.get_tool())

    def actionPerformed(self, context):
        self.undo_hijacked_files(context.selected_files)

    def is_enabled_for_context(self, context):
        if self.is_file_system_busy():
            return False

        domain_files = context.selected_files
        for file in domain_files:
            if file.is_hijacked():
                return True

        return False

    def undo_hijacked_files(self, domain_files):
        if not self.check_repository_connected():
            return

        hijack_list = []
        for file in domain_files:
            if file is not None and file.is_hijacked():
                hijack_list.append(file)

        self.undo_hijack(hijack_list)

    def undo_hijack(self, hijack_list):
        if not self.check_repository_connected():
            return

        if len(hijack_list) > 0:
            dialog = UndoActionDialog("Confirm Undo Hijack", "images/undo_hijack.png", "Undo_Hijack", "hijack", hijack_list)
            action_id = dialog.show_dialog(self.plugin.get_tool())

            if action_id != UndoActionDialog.CANCEL:
                save_copy = dialog.save_copy()
                files = dialog.selected_domain_files
                if len(files) > 0:
                    self.plugin.execute(UndoHijackTask(files, save_copy))

    def get_keep_name(self, parent, name):
        one_up = 1
        keep_name = f"{name}.keep"
        while True:
            df = parent.get_file(keep_name)
            if df is not None:
                keep_name = f"{name}.keep{one_up}"
                one_up += 1

            return keep_name


class UndoHijackTask(Task):
    def __init__(self, hijack_files, save_copy):
        super().__init__("Undo Hijack", True, True, True)
        self.hijack_files = hijack_files
        self.save_copy = save_copy

    def run(self, monitor):
        try:
            for current_df in self.hijack_files:
                monitor.check_canceled()
                monitor.set_message(f"Undoing Hijack {current_df.name}")
                if self.save_copy:
                    # rename the file
                    try:
                        current_df.name = f"{get_keep_name(current_df.parent, current_df.name)}"
                    except InvalidNameException as e1:
                        pass  # TODO put error message here

                else:
                    current_df.delete()
        except CancelledException as e:
            self.plugin.status_info("Undo hijack was canceled")
        except IOException as e:
            ClientUtil.handle_exception(self.repository, e, "Undo Hijack", self.plugin.get_tool_frame())
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation.