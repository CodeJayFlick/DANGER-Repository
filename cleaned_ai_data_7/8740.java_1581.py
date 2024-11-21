import os
from ghidra_scripts import GhidraScript, VTSessionDB, Program, DomainFolder, PluginTool, AutoVersionTrackingCommand, VTControllerImpl


class AutoVersionTrackingScript(GhidraScript):
    def run(self) -> None:
        folder = self.ask_project_folder("Please choose a folder for your Version Tracking session.")
        name = input(f"Please enter a Version Tracking session name ({folder.name}): ")

        source_program: Program
        destination_program: Program

        is_current_program_source_prog = self.ask_yes_no(
            "Current Program Source Program?",
            "Is the current program your source program?"
        )

        if is_current_program_source_prog:
            source_program = self.current_program
            destination_program = self.ask_program("Please select the destination (new) program")
        else:
            destination_program = self.current_program
            source_program = self.ask_program("Please select the source (existing annotated) program")

        # Need to end the script transaction or it interferes with vt things that need locks
        self.end(True)

        session: VTSession = VTSessionDB.create_vt_session(name, source_program, destination_program, self)
        folder.create_file(name, session, self.monitor)

        tool: PluginTool = self.state.get_tool()
        plugin: VTPlugin | None = self.get_plugin(tool, VTPlugin)
        if plugin is None:
            tool.add_plugin(VTPlugin.__name__)
            plugin = self.get_plugin(tool, VTPlugin)

        controller: VTControllerImpl = VTControllerImpl(plugin)

        # String description = "AutoVTScript";

        auto_vt_cmd: AutoVersionTrackingCommand = AutoVersionTrackingCommand(
            controller,
            session,
            1.0,
            10.0
        )

        plugin.get_tool().execute_background_command(auto_vt_cmd, session)
        # destination_program.save(description, self.monitor);
        # session.save(description, self.monitor);
        # session.release(self);

    def get_plugin(self, tool: PluginTool, c: type[Plugin]) -> T | None:
        plugins = list(tool.get_managed_plugins())
        for p in plugins:
            if isinstance(p, c):
                return cast(c, p)
        return None

    @staticmethod
    def ask_project_folder(prompt: str) -> DomainFolder:
        # implement this method to prompt the user and get a folder
        pass

    @staticmethod
    def ask_string(prompt: str, default_value: str = "") -> str:
        # implement this method to prompt the user for input
        pass

    @staticmethod
    def ask_yes_no(prompt: str) -> bool:
        # implement this method to prompt the user and get a yes/no response
        pass

    @staticmethod
    def ask_program(prompt: str) -> Program:
        # implement this method to prompt the user for input (a program)
        pass


if __name__ == "__main__":
    script = AutoVersionTrackingScript()
    try:
        script.run()
    except Exception as e:
        print(f"An error occurred: {e}")
