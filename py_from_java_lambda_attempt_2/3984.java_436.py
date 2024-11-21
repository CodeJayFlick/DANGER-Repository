Here is the translation of the given Java code into equivalent Python:

```Python
import threading

class SearchInstructionsTask:
    def __init__(self, search_dialog, plugin):
        self.search_dialog = search_dialog
        self.plugin = plugin

    def run(self, task_monitor=None):
        if not task_monitor:
            return

        # Get all the search ranges we have to search.
        search_ranges = self.search_dialog.get_control_panel().get_range_widget().get_search_range()

        # Get the current cursor location - we'll always start searching from here.
        current_addr = self.plugin.get_program_location().get_byte_address()

        # See if we're searching forward or backwards.
        is_forward = self.search_dialog.get_control_panel().get_direction_widget().get_search_direction() == "FORWARD"

        # If we're searching backwards, we need to process address ranges in reverse so reverse the list.
        if not is_forward:
            search_ranges.reverse()

        range_num = 0

        for range_ in search_ranges:
            range_num += 1
            if is_forward and current_addr >= range_.get_max_address():
                continue
            elif not is_forward and current_addr <= range_.get_min_address():
                continue

            task_monitor.set_message(f"Searching range {range_num} of {len(search_ranges)}")

            # And SEARCH.
            search_results = self.search_dialog.get_search_data().search(self.plugin, range_, task_monitor, is_forward)

            if search_results:
                threading.Thread(target=self.go_to_location, args=(search_results.get_addr(),)).start()
                return

        self.search_dialog.get_message_panel().set_text("No results found", "blue")
        return

    def go_to_location(self, addr):
        gs = self.plugin.get_tool().get_service(GoToService)
        bloc = BytesFieldLocation(self.plugin.get_current_program(), addr)
        gs.go_to(bloc)

class InstructionMetadata:
    pass

class GoToService:
    def __init__(self, tool):
        self.tool = tool

    def go_to(self, bloc):
        # implement the actual goTo functionality
        pass

class BytesFieldLocation:
    def __init__(self, program, addr):
        self.program = program
        self.addr = addr

# Usage example:

search_dialog = ...  # initialize your search dialog here
plugin = ...  # initialize your plugin here

task = SearchInstructionsTask(search_dialog, plugin)
task.run()
```

Please note that this is a direct translation of the given Java code into equivalent Python.