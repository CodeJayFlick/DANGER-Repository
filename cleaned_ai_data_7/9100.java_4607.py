class SummaryPanel:
    def __init__(self):
        self.label_label = None
        self.summary_label = None
        self.help_name = "Add_To_Session_Summary_Panel"

    def dispose(self):
        pass  # nothing to do

    def get_help_location(self):
        return {"plugin": "VersionTrackingPlugin", "help_name": self.help_name}

    def enter_panel(self, state):
        label_text = ""
        summary_text = ""

        if 'wizard_op_description' in state:
            op_description = state['wizard_op_description']
            help_name = f"New_Session_Summary_Panel" if op_description.startswith("New") else "Add_To_Session_Summary_Panel"
            self.help_name = help_name
            label_text += "Operation:<br>"
            summary_text += str(op_description) + "<br>"

        session_name = state.get('session_name', None)
        if session_name:
            label_text += f"Session Name: {session_name}<br>"
            summary_text += f"{session_name}<br>"

        source_program_name = state.get('source_program_file', {}).get('name', None)
        destination_program_name = state.get('destination_program_file', {}).get('name', None)

        label_text += "Source Program:<br>"
        if not source_program_name:
            summary_text += "(null)<br>"
        else:
            summary_text += HTMLUtilities.escape_html(source_program_name) + "<br>"

        label_text += "Destination Program:<br>"
        if not destination_program_name:
            summary_text += "(null)<br>"
        else:
            summary_text += HTMLUtilities.escape_html(destination_program_name) + "<br>"

        correlator_label = ""
        for correlator_factory in state.get('program_correlator_factory_list', []):
            label_text += f"{correlator_label}Program Correlator:<br>"
            if not correlator_factory:
                summary_text += "(null)<br>"
            else:
                summary_text += str(correlator_factory) + "<br>"

        exclude_accepted_matches = state.get('exclude_accepted_matches', None)
        show_address_set_panels = state.get('show_address_set_panel', None)

        if exclude_accepted_matches is not None and isinstance(exclude_accepted_matches, bool):
            label_text += f"Exclude Accepted Matches: {'Yes' if exclude_accepted_matches else 'No'}<br>"
            summary_text += "Yes" if exclude_accepted_matches else "No"

        manually_specified_addresses = show_address_set_panels is not None and show_address_set_panels
        source_address_set_choice = state.get('source_address_set_choice', AddressSetChoice.MANUALLY_DEFINED)
        destination_address_set_choice = state.get('destination_address_set_choice', AddressSetChoice.MANUALLY_DEFINED)

        if manually_specified_addresses:
            label_text += "Source Address Set:<br>"
            summary_text += source_address_set_choice.name + "<br>"

            label_text += "Destination Address Set:<br>"
            summary_text += destination_address_set_choice.name + "<br>"

        self.label_label = GDHtmlLabel(label_text)
        self.summary_label = GDHtmlLabel(summary_text)

    def get_correlators(self, state):
        correlator_list = state.get('program_correlator_factory_list', None)
        if not correlator_list:
            return []
        else:
            return [correlator for correlator in correlator_list]

    def get_panel_displayability_and_update_state(self, state):
        return WizardPanelDisplayability.CAN_BE_DISPLAYED

    def leave_panel(self, state):
        self.update_state_object_with_panel_info(state)

    def update_state_object_with_panel_info(self, state):
        pass  # nothing to do

    def get_title(self):
        return "Summary"

    def initialize(self):
        pass  # nothing to do

    def is_valid_information(self):
        return True

    def add_dependencies(self, state):
        pass  # no dependencies; we just confirm what's going to happen
