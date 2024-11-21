Here is the translation of the given Java code into equivalent Python:

```Python
class CreateDiffTask:
    def __init__(self, plugin: 'ProgramDiffPlugin', program1: 'Program', 
                 program2: 'Program', limited_address_set_view: 'AddressSetView',
                 is_limited_to_selection: bool, diff_filter: 'ProgramDiffFilter',
                 apply_filter: 'ProgramMergeFilter'):
        self.plugin = plugin
        self.program1 = program1
        self.program2 = program2
        self.limited_address_set = limited_address_set_view
        self.is_limited_to_selection = is_limited_to_selection
        self.diff_filter = diff_filter
        self.apply_filter = apply_filter

    def run(self, monitor: 'TaskMonitor'):
        if self.plugin.is_task_in_progress():
            return
        
        try:
            dc = None
            self.plugin.set_task_in_progress(True)
            monitor.set_indeterminate(True)
            monitor.set_message("Checking Program Differences")
            
            try:
                dc = DiffController(self.program1, self.program2,
                                      self.limited_address_set, self.diff_filter,
                                      self.apply_filter, monitor)
                
                filtered_differences = dc.get_filtered_differences(monitor)
                no_filtered_differences_found = filtered_differences.is_empty()
                
                self.plugin.set_diff_controller(dc)
                dc.differences_changed(monitor)
                dc.set_location(self.plugin.current_address())
                monitor.set_message("Done")
                
                r = lambda: display_differences_message_if_necessary(no_filtered_differences_found)
                SwingUtilities.invokeLater(r)
            except DomainObjectException as e:
                cause = e.cause
                if isinstance(cause, ClosedException):
                    pass  # this can happen if you close the tool while this task is calculating diffs
                else:
                    raise e
            
            except ProgramConflictException as e:
                show_error_message(e.message)
            
            catch CancelledException as e:
                self.plugin.set_diff_controller(dc)

        finally:
            completed()

    def display_differences_message_if_necessary(self, no_filtered_differences_found):
        try:
            program_memory_comparator = ProgramMemoryComparator(self.program1,
                                                                 self.program2)
            has_memory_differences = program_memory_comparator.has_memory_differences()
            
            title = None
            message = None
            
            if self.is_limited_to_selection:
                if no_filtered_differences_found:
                    title = "No Differences In Selection"
                    message = f"No differences were found for the addresses in the selection" \
                              f"\nand for the types of program information being compared by this Diff."
                else:
                    pass  # Not a diff on a selection, memory is the same, and no differences found 
            else:
                if has_memory_differences:
                    title = "Memory Differs"
                    message = get_memory_difference_message(no_filtered_differences_found,
                                                             program_memory_comparator)
                elif no_filtered_differences_found:
                    title = "No Differences"
                    message = f"No differences were found for the addresses that are compatible between" \
                              f"\nthe two programs for the types of program information being compared by this Diff."
            
            if title is not None:
                note = "\n  \nNote: Some parts of the program are not handled by Diff (for example:" \
                       "\n         Markup where only one program has that memory address," \
                       "\n         Registers that are not common to both programs' languages," \
                       "\n         Program Trees, Data Types that haven't been applied to memory, etc.)"
                
                Msg.show_info(self.__class__, self.plugin.listing_panel(), title,
                              message + note)
        except ProgramConflictException as e:
            show_error_message("Can't Compare Memory")
        
    def get_memory_difference_message(self, no_filtered_differences_found,
                                       program_memory_comparator):
        message = f"The memory addresses defined by the two programs are not the same.\n  \n" \
                  (f"No differences were found " if no_filtered_differences_found else 
                   f"Differences are highlighted ") + \
                  f"for the addresses that are compatible between\nthe two programs for the types of program information being compared by this Diff."
        
        addresses_only_in_one = program_memory_comparator.get_addresses_only_in_one()
        if not addresses_only_in_one.is_empty():
            message += f"\n  \nSome addresses are only in program 1 : {addresses_only_in_one}"
        
        addresses_only_in_two = program_memory_comparator.get_addresses_only_in_two()
        if not addresses_only_in_two.is_empty():
            message += f"\n  \nSome addresses are only in program 2 : {addresses_only_in_two}"
        
        return message
    
    def show_error_message(self, message):
        SystemUtilities.run_swing_later(lambda: Msg.show_error(self.__class__,
                                                                  self.plugin.tool().tool_frame(),
                                                                  "Can't Perform Diff", message))
    
    def completed(self):
        if self.plugin.is_disposed():
            # the tool was closed while this task was running
            return
        
        if not self.plugin.current_program():
            # the program was closed while this task was running
            return
        
        SystemUtilities.run_swing_later(lambda: 
                                        diff_apply_settings_provider = self.plugin.get_diff_apply_settings_provider()
                                        diff_apply_settings_provider.configure(self.apply_filter)
                                        self.plugin.adjust_diff_display())
        
        self.plugin.set_task_in_progress(False)

```

Note that Python does not have direct equivalent of Java's Swing, so the code is translated as best possible.