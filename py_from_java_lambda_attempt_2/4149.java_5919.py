Here is the translation of the Java code into Python:

```Python
class ProgramSaveManager:
    def __init__(self, tool: 'PluginTool', program_mgr: 'ProgramManager'):
        self.tool = tool
        self.program_mgr = program_mgr
        self.domain_file_filter = lambda f: isinstance(f.get_domain_object_class(), type(Program))

    def can_close(self, program: Program) -> bool:
        if not (program and program.get_domain_file().get_consumers().size() > 1):
            return True

        if acquire_save_lock(program, "Close"):
            try:
                return handle_changed_program(program)
            finally:
                program.unlock()

        return False

    def can_close_all(self) -> bool:
        programs = self.program_mgr.get_all_open_programs()
        save_list = []
        lock_list = []

        for program in programs:
            if is_only_tool_consumer(program):
                if not acquire_save_lock(program, "Close"):
                    return False
                lock_list.append(program)
                save_list.append(program)

            elif is_analysis_tool(program):
                if not acquire_save_lock(program, "Close"):
                    return False
                lock_list.append(program)

        return self.save_changed_programs(save_list)

    def save_changed_programs(self, open_program_list: list) -> bool:
        dialog = SaveDataDialog(self.tool)
        domain_files_to_save = []

        for program in open_program_list:
            if not program.get_domain_file().is_changed():
                continue
            else:
                domain_files_to_save.append(program.get_domain_file())

        if len(open_program_list) == 0:
            return True

        elif len(open_program_list) == 1:
            return self.can_close(open_program_list[0])

        return dialog.show_dialog(domain_files_to_save)

    def save_program(self, program: Program):
        if not (program and program.is_changed()):
            return
        if program.get_domain_file().is_in_writable_project():
            self.save(program)
        else:
            self.save_as(program)

    def save(self, program: Program):
        self.tool.prepare_to_save(program)
        if acquire_save_lock(program, "Save"):
            try:
                task = SaveFileTask(program.get_domain_file())
                new TaskLauncher(task, self.tool.get_tool_frame())

            finally:
                program.unlock()

    def save_as(self, program: Program):
        if not get_save_as_lock(program):
            return
        try:
            dialog = self.get_save_dialog()
            filename = program.get_domain_file().get_name()
            dialog.set_title("Save As (" + filename + ")")
            dialog.set_name_text(filename + ".1")
            dialog.set_selected_folder(program.get_domain_file().get_parent())
            tree_dialog_cancelled = True
            self.tool.show_dialog(dialog)
            if not tree_dialog_cancelled:
                self.save_as(program, dialog.get_domain_folder(), dialog.get_name_text())

        finally:
            program.unlock()

    def save_as(self, current_program: Program, folder: DomainFolder, name: str):
        existing_file = folder.get_file(name)
        if existing_file == current_program.get_domain_file():
            self.save(current_program)
            return
        elif existing_file is not None:
            msg = "Program " + name + " already exists. Do you want to overwrite it?"
            if OptionDialog.show_option_dialog(self.tool.get_tool_frame(), "Duplicate Name", msg, "&Save", "Do&n't Save", OptionDialog.WARNING_MESSAGE) == OptionDialog.CANCEL_OPTION:
                return
        self.save_as(current_program)

    def handle_changed_program(self, current_program: Program) -> bool:
        if not (current_program and current_program.is_changed()):
            return True

        df = current_program.get_domain_file()

        filename = df.get_name()
        if not df.is_in_writable_project():
            msg = "Viewed file '" + HTMLUtilities.escape_html(filename) + "' has been changed. If you continue, your changes will be lost!"
            result = OptionDialog.show_option_dialog(self.tool.get_tool_frame(), "Save Program?", msg, "&Save", "Do&n't Save", OptionDialog.WARNING_MESSAGE)
            if result == OptionDialog.CANCEL_OPTION:
                return False
        elif df.is_read_only():
            msg = "Read-only file '" + HTMLUtilities.escape_html(filename) + "' has been changed. If you continue, your changes will be lost!"
            result = OptionDialog.show_option_dialog(self.tool.get_tool_frame(), "Save Program?", msg, "&Save", "Do&n't Save", OptionDialog.WARNING_MESSAGE)
            if result == OptionDialog.CANCEL_OPTION:
                return False

        result = OptionDialog.show_option_dialog(self.tool.get_tool_frame(), "Save Program?", filename + " has changed. Do you want to save it?")
        if result == OptionDialog.CANCEL_OPTION:
            return False
        elif result == OptionDialog.ONE_OPTION:
            self.save(current_program)
        return True

    def acquire_save_lock(self, program: Program, action_name: str) -> bool:
        if not (program and program.lock(None)):
            title = "Save " + action_name + " (Busy)"
            buf = StringBuffer()
            buf.append("The Program is currently being modified by the following actions/tasks:\n")
            t = program.get_current_transaction()
            list = t.get_open_sub_transactions()
            it = iter(list)
            while True:
                try:
                    item = next(it)
                    buf.append("\n      " + str(item))
                except StopIteration:
                    break
            buf.append("\n  \n")
            buf.append("WARNING! The above task(s) should be cancelled before attempting a Save " + action_name + ". Only proceed if unable to cancel them.\n")

            result = OptionDialog.show_option_dialog(self.tool.get_tool_frame(), title, str(buf), "Save As (Rollback)", "Save As (As Is)", OptionDialog.WARNING_MESSAGE)
            if result == OptionDialog.ONE_OPTION:
                program.force_lock(True, action_name)
                return True
            elif result == OptionDialog.TWO_OPTION:
                program.force_lock(False, action_name)
                return True

        return True

    def get_save_as_lock(self, program: Program) -> bool:
        if not (program and program.lock(None)):
            title = "Save As (Busy)"
            buf = StringBuffer()
            buf.append("The Program is currently being modified by the following actions/tasks:\n")
            t = program.get_current_transaction()
            list = t.get_open_sub_transactions()
            it = iter(list)
            while True:
                try:
                    item = next(it)
                    buf.append("\n      " + str(item))
                except StopIteration:
                    break
            buf.append("\n  \n")
            buf.append("WARNING! The above task(s) should be cancelled before attempting a Save As... Only proceed if unable to cancel them.\n")

            result = OptionDialog.show_option_dialog(self.tool.get_tool_frame(), title, str(buf), "Save As (Rollback)", "Save As (As Is)", OptionDialog.WARNING_MESSAGE)
            if result == OptionDialog.ONE_OPTION:
                program.force_lock(True, action_name)
                return True
            elif result == OptionDialog.TWO_OPTION:
                program.force_lock(False, action_name)
                return True

        return True

    def get_save_dialog(self) -> 'DataTreeDialog':
        if self.data_tree_save_dialog is None:
            listener = lambda event: self.save_as(event.get_domain_folder(), event.get_name_text())
            self.data_tree_save_dialog = DataTreeDialog(None, "Save As", DataTreeDialog.SAVE, self.domain_file_filter)
            self.data_tree_save_dialog.add_ok_action_listener(listener)

        return self.data_tree_save_dialog

    class SaveFileTask(Task):
        def __init__(self, domain_file: DomainFile):
            super("Save Program", True, True, True)
            self.domain_file = domain_file

        def run(self, monitor) -> None:
            monitor.set_message("Saving Program...")
            try:
                self.domain_file.save(monitor)

            except CancelledException as e:
                # ignore
                pass

            except NotConnectedException as e:
                ClientUtil.prompt_for_reconnect(tool.get_project().get_repository(), tool.get_tool_frame())

            except ConnectException as e:
                ClientUtil.prompt_for_reconnect(tool.get_project().get_repository(), tool.get_tool_frame())

            except IOException as e:
                Msg.show_error(self, None, "Program SaveAs Error", str(e))

    class SaveAsTask(Task):
        def __init__(self, domain_obj: DomainObject, folder: DomainFolder, name: str, do_overwrite: bool):
            super("Save Program As", True, True, True)
            self.domain_obj = domain_obj
            self.folder = folder
            self.name = name
            self.do_overwrite = do_overwrite

        def run(self, monitor) -> None:
            monitor.set_message("Saving Program...")
            try:
                if self.do_overwrite:
                    df = self.folder.get_file(self.name)
                    if df is not None:
                        df.delete()
                    else:
                        self.folder.create_file(self.name, self.domain_obj, monitor)

                else:
                    parent_folder = self.folder
                    new_name = self.name
                    existing_file = parent_folder.get_file(new_name)
                    if existing_file == self.domain_obj:
                        self.save_as(self.domain_obj)
                        return

            except CancelledException as e:
                # ignore
                pass

            except IOException as e:
                Msg.show_error(self, None, "Program SaveAs Error", str(e))

    class DataTreeDialog(Dialog):
        def __init__(self, parent: 'JFrame', title: str, message: str, option_type: int):
            super(title)
            self.parent = parent
            self.title = title
            self.message = message
            self.option_type = option_type

        def show_dialog(self) -> None:
            result = OptionDialog.show_option_dialog(self.parent, "Duplicate Name", self.message, "&Save", "Do&n't Save", self.option_type)
            if result == OptionDialog.CANCEL_OPTION:
                return False
            elif result == OptionDialog.ONE_OPTION:
                # save the file
                pass

        def set_title(self, title: str) -> None:
            self.title = title

        def set_name_text(self, name: str) -> None:
            self.name_text = name

        def get_domain_folder(self) -> DomainFolder:
            return self.domain_folder

    class OptionDialog(Dialog):
        ONE_OPTION = 1
        CANCEL_OPTION = -1
        TWO_OPTION = 2