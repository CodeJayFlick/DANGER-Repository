import os
from ghidra_fileformats import GhidraFileChooser, FSBActionContext, FSBRootNode, FSBFileNode, PrelinkFileSystem
from ghidra_framework_plugintool import PluginStatus, FrontEndable

class FileFormatsPlugin(FrontEndable):
    def __init__(self, tool):
        super().__init__()
        self.chooser_eclipse = None
        self.chooser_jar_folder = None
        self.actions = []

    def init(self):
        for action in [self.create_eclipse_project_action(), 
                       self.create_decompile_jar_action(), 
                       self.create_crypto_template_action(), 
                       self.create_load_kernel_action()]:
            self.get_tool().add_action(action)

    def dispose(self):
        for action in self.actions:
            self.get_tool().remove_action(action)
        self.chooser_eclipse = None
        self.chooser_jar_folder = None

    @staticmethod
    def is_apk(fsrl):
        return fsrl and fsrl.name and "apk".lower() == os.path.splitext(fsrl.name)[1].lower()

    def do_export_to_eclipse(self, fsrl, output_directory, monitor):
        try:
            refd_file = FileSystemService.get_instance().get_refd_file(fsrl, monitor)
            android_project_creator = AndroidProjectCreator(refd_file.file.fsrl, output_directory)
            creator.create(monitor)

            if creator.log.has_messages():
                Msg.show_info(self, self.get_tool().active_window(), "Export to Eclipse Project", str(creator.log))
        except (IOException, CancelledException) as e:
            FSUtilities.display_exception(self, self.get_tool().active_window(), "Error Exporting to Eclipse", e)

    def create_eclipse_project_action(self):
        return ActionBuilder("FSB Export Eclipse Project", self.name).with_context(FSBActionContext).enabled_when(lambda ac: not ac.is_busy() and JadProcessWrapper.is_jad_present() and FileFormatsPlugin.is_apk(ac.file_fsrl)).popup_menu_path("Export Eclipse Project").popup_menu_icon(ImageManager.ECLIPSE).on_action(self.do_export_to_eclipse)

    def create_decompile_jar_action(self):
        return ActionBuilder("FSB Decompile JAR", self.name).with_context(FSBActionContext).enabled_when(lambda ac: not ac.is_busy() and JadProcessWrapper.is_jad_present()).popup_menu_path("Decompile JAR").on_action(self.decompile_jar)

    def decompile_jar(self, fsrl):
        if fsrl:
            chooser = GhidraFileChooser(None)
            chooser.set_file_selection_mode(GhidraFileChooserMode.DIRECTORIES_ONLY)
            chooser.set_title("Select JAR Output Directory")
            chooser.set_approve_button_text("SELECT")

            output_directory = chooser.get_selected_file()
            g_tree = self.get_tool().active_window()

            if output_directory:
                try:
                    jar_decompiler = JarDecompiler(fsrl, output_directory)
                    decompiler.decompile(monitor)

                    if decompiler.log.has_messages():
                        Msg.show_info(self, g_tree, "Decompiling JAR", str(decompiler.log))
                except Exception as e:
                    FSUtilities.display_exception(self, g_tree, "Error Decompiling Jar", e.message, e)

    def create_crypto_template_action(self):
        return ActionBuilder("FSB Create Crypto Key Template", self.name).with_context(FSBActionContext).enabled_when(lambda ac: not ac.is_busy() and isinstance(ac.selected_node, FSBRootNode) and ac.file_fsrl).on_action(self.create_crypto_template)

    def create_crypto_template(self, fsrl):
        try:
            writer = CryptoKeyFileTemplateWriter(fsrl.get_container_name())
            if writer.exists():
                answer = OptionDialog.show_yes_no_dialog(None, "WARNING!! Crypto Key File Already Exists", "Are you really sure that you want to overwrite it?")

                if answer == OptionDialog.NO_OPTION:
                    return

            writer.open()
            try:
                self.write_file(writer, ac.selected_node.get_children())
            finally:
                writer.close()

        except IOException as e:
            FSUtilities.display_exception(self, None, "Error writing crypt key file", e.message, e)

    def write_file(self, writer, children):
        if not children or len(children) == 0:
            return

        for child in children:
            if isinstance(child, FSBFileNode):
                fsrl = child.get_fsrl()
                writer.write(fsrl.name)
            else:
                self.write_file(writer, child.get_children())

    def create_load_kernel_action(self):
        return ActionBuilder("FSB Load iOS Kernel", self.name).with_context(FSBActionContext).enabled_when(lambda ac: not ac.is_busy() and isinstance(ac.selected_node, FSBRootNode) and isinstance(ac.selected_node.fs_ref.filesystem(), PrelinkFileSystem)).on_action(self.load_ios_kernel)

    def load_ios_kernel(self):
        pm = FSBUtils.get_program_manager(self.get_tool(), True)
        if pm:
            TaskLauncher.launch(GFileSystemLoadKernelTask(self, pm, self.actions))
