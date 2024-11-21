import tkinter as tk
from typing import Any

class MultiTabPlugin:
    def __init__(self):
        self.tab_panel = None
        self.prog_service = None
        self.cv_service = None
        self.go_to_program_action = None
        self.go_to_last_active_program_action = None
        self.go_to_next_program_action = None
        self.go_to_previous_program_action = None
        self.select_highlighted_program_timer = None

    def create_actions(self):
        first_group = "1"
        second_group = "2"

        self.go_to_program_action = tk.Button("Go To Program", name=self.name)
        self.go_to_program_action.config(command=lambda: self.show_program_list())
        self.go_to_program_action.group_data = (ToolConstants.MENU_NAVIGATION, "Go To Program...", ToolConstants.MENU_NAVIGATION_GROUP_WINDOWS, MenuData.NO_MNEMONIC, first_group)

        self.go_to_next_program_action = tk.Button("Go To Next Program", name=self.name)
        self.go_to_next_program_action.config(command=lambda: self.next_program_pressed())
        self.go_to_next_program_action.group_data = (ToolConstants.MENU_NAVIGATION, "Go To Next And Previous Program")

        self.go_to_previous_program_action = tk.Button("Go To Previous Program", name=self.name)
        self.go_to_previous_program_action.config(command=lambda: self.previous_program_pressed())
        self.go_to_previous_program_action.group_data = (ToolConstants.MENU_NAVIGATION, "Go To Next And Previous Program")

        self.select_highlighted_program_timer = tk.Timer(750, lambda e: self.select_highlighted_program())

    def update_action_enablement(self):
        enable = tab_panel.get_tab_count() > 1
        self.go_to_program_action.config(state="normal" if enable else "disabled")
        self.go_to_next_program_action.config(state="normal" if enable else "disabled")
        self.go_to_previous_program_action.config(state="normal" if enable else "disabled")

    def switch_to_program(self, program):
        if last_active_program is not None:
            tab_panel.set_selected_program(last_active_program)

    def show_program_list(self):
        tab_panel.show_program_list()

    def highlight_next_program(self, forward_direction):
        tab_panel.highlight_next_program(forward_direction)
        self.select_highlighted_program_timer.restart()

    def select_highlighted_program(self):
        tab_panel.select_highlighted_program()

    def get_string_used_in_list(self, program):
        domain_file = program.get_domain_file()
        change_indicator = "*" if program.is_changed() else ""
        return f"{domain_file} {change_indicator}"

    def get_tooltip(self, program):
        return self.get_string_used_in_list(program)

    def name(self, program):
        domain_file = program.get_domain_file()
        tab_name = domain_file.name
        if not domain_file.can_save and domain_file.version != DomainFile.DEFAULT_VERSION:
            tab_name += f" @{domain_file.version}"
        if not domain_file.is_readable():
            tab_name += " [Read-Only]"
        return tab_name

    def key_typed_from_list_window(self, e):
        stroke = KeyStroke.get_key_stroke_for_event(e)
        if stroke == NEXT_TAB_KEYSTROKE:
            self.next_program_pressed()
        elif stroke == PREVIOUS_TAB_KEYSTROKE:
            self.previous_program_pressed()

    def next_program_pressed(self):
        self.highlight_next_program(True)
        self.select_highlighted_program_timer.restart()

    def previous_program_pressed(self):
        self.highlight_next_program(False)
        self.select_highlighted_program_timer.restart()

    def is_changed(self, obj):
        return isinstance(obj, Program) and obj.is_changed

    def domain_object_changed(self, ev):
        if isinstance(ev.source, Program):
            program = ev.source
            tab_panel.refresh(program)

    def remove_program(self, program):
        return prog_service.close_program(program, False)

    def program_selected(self, program):
        if program != prog_service.current_program:
            prog_service.set_current_program(program)
