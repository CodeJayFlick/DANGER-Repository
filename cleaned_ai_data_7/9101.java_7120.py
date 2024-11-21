class VTAddToSessionWizardManager:
    def __init__(self, controller):
        self.controller = controller
        state = {}
        source_program = self.controller.get_source_program()
        destination_program = self.controller.get_destination_program()
        session = self.controller.get_session()

        state[VTWizardStateKey.SOURCE_PROGRAM] = source_program
        state[VTWizardStateKey.DESTINATION_PROGRAM] = destination_program
        state[VTWizardStateKey.SOURCE_PROGRAM_FILE] = source_program.domain_file
        state[VTWizardStateKey.DESTINATION_PROGRAM_FILE] = destination_program.domain_file
        state[VTWizardStateKey.EXISTING_SESSION] = session
        state[VTWizardStateKey.SESSION_NAME] = session.name
        state[VTWizardStateKey.WIZARD_OP_DESCRIPTION] = "Add to Version Tracking Session"
        state[VTWizardStateKey.SOURCE_SELECTION] = self.controller.get_selection_in_source_tool()
        state[VTWizardStateKey.DESTINATION_SELECTION] = self.controller.get_selection_in_destination_tool()

    def create_panels(self):
        panels = []
        panels.append(CorrelatorPanel(self.controller.session))
        panels.append(OptionsPanel())
        panels.append(AddressSetOptionsPanel())
        panels.append(LimitAddressSetsPanel(self.controller.tool))
        panels.append(SummaryPanel())
        return panels

    def do_finish(self):
        try:
            task = AddToSessionTask(self.controller, self.state)
            TaskLauncher(task, self.wizard_manager.component).start()
        finally:
            self.wizard_manager.completed(True)

class MagePanelManager(VTAddToSessionWizardManager):
    pass
