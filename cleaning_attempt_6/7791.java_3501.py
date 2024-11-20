class WindowsResourceReferenceAnalyzer:
    NAME = "WindowsResourceReference"
    DESCRIPTION = "Given certain Key windows API calls, tries to create references at the use of windows Resources."

    def __init__(self):
        self.create_bookmarks_enabled = True

    def can_analyze(self, program):
        if program.executable_format == 'PE':
            return True
        else:
            return False

    def added(self, program, address_set_view, task_monitor, message_log):
        try:
            script_name = "WindowsResourceReference. java"
            analysis_manager = AutoAnalysisManager.get_analysis_manager(program)
            tool = analysis_manager.get_analysis_tool()
            project = self.find_project(tool)

            state = GhidraState(tool, project, program,
                                 ProgramLocation(program, address_set_view.min_address),
                                 ProgramSelection(address_set_view), None)

            source_file = GhidraScriptUtil.find_script_by_name(script_name)
            if source_file is not None:
                provider = GhidraScriptUtil.get_provider(source_file)
                script = provider.get_script_instance(source_file, message_log)
                state.set(state, task_monitor, message_log)

                # This code was added so the analyzer won't print script messages to console
                # This also adds the ability to pass the option to add or not add bookmarks to the script
                create_bookmarks_enabled = self.create_bookmarks_enabled

                if create_bookmarks_enabled:
                    writer = get_output_msg_stream(tool)
                    script.run_script(script_name, [str(create_bookmarks_enabled)])
            else:
                raise IllegalAccessException("Couldn't find script")

        except Exception as e:
            print(f"Error running script: {script_name}\n{e}")

    def removed(self, program, address_set_view, task_monitor, message_log):
        return False

    def register_options(self, options, program):
        options.register_option('Create Analysis Bookmarks', self.create_bookmarks_enabled,
                                None, 'Select this check box if you want this analyzer to create analysis bookmarks when items of interest are created/identified by the analyzer.')

    def options_changed(self, options, program):
        self.create_bookmarks_enabled = options.get_boolean('Create Analysis Bookmarks',
                                                            self.create_bookmarks_enabled)

class GhidraState:
    def __init__(self, tool, project, program, location, selection, state=None):
        pass

def get_output_msg_stream(tool):
    if tool is not None:
        console_service = tool.get_service(ConsoleService)
        return console_service.get_std_out()
    else:
        return PrintWriter(sys.stdout)

class AutoAnalysisManager:
    @staticmethod
    def get_analysis_manager(program):
        # This method should be implemented based on the actual implementation of Java's AutoAnalysisManager.
        pass

def find_project(tool):
    if tool is not None:
        return tool.get_project()
    else:
        return None

# Usage example:

analyzer = WindowsResourceReferenceAnalyzer()

program = Program()  # You need to implement this class
address_set_view = AddressSetView(program)  # You need to implement these classes

try:
    analyzer.added(program, address_set_view, task_monitor=None, message_log=None)
except Exception as e:
    print(f"Error running script: {script_name}\n{e}")
