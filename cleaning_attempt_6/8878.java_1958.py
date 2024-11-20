class ApplyBlockedMatchAction:
    NAME = "Apply Blocked Match"
    MENU_GROUP = VTPlugin.EDIT_MENU_GROUP

    def __init__(self, controller):
        self.controller = controller
        super().__init__(NAME, VTPlugin.OWNER)
        set_popup_menu_data(new MenuData([f"{NAME}"], Icons.APPLY_BLOCKED_MATCH_ICON, MENU_GROUP))
        set_enabled(False)
        help_location = HelpLocation("VersionTrackingPlugin", "Apply_Blocked_Match")
        self.set_help_location(help_location)

    def actionPerformed(self, context):
        match_context = VTMatchContext(context)
        matches = list(match_context.get_selected_matches())
        if len(matches) != 1:
            return
        match = matches[0]
        association = match.get_association()
        status = association.get_status()
        if status != VTAssociationStatus.BLOCKED:
            return
        conflicts = self.get_conflicting_matches(match)
        conflict_message = self.get_conflicting_matches_display_string(match, conflicts)
        response = OptionDialog.show_option_dialog(None, "Clear Conflicting Matches and Apply?", conflict_message,
                                                      "Clear and Apply", OptionDialog.QUESTION_MESSAGE)
        if response == OptionDialog.OPTION_ONE:
            task = ApplyBlockedMatchTask(self.controller, match, conflicts)
            self.controller.run_vt_task(task)

    def get_conflicting_matches(self, match):
        associations = list(match.get_association().get_related_associations())
        conflicting_associations = [association for association in associations if
                                     association.get_status() == VTAssociationStatus.ACCEPTED]
        return conflicting_associations

    def get_conflicting_matches_display_string(self, match, conflicts):
        buffer = "<html>"
        count = 0
        for conflict in conflicts:
            if conflict.get_status() == VTAssociationStatus.ACCEPTED:
                buffer += f"Conflicting {self.get_association_display_string(conflict)}.<br>"
                count += 1
        buffer += " <br>"
        buffer += f"Do you want to clear the conflicting accepted match{'' if count <= 1 else 'es'} and all their applied markup items<br>and then apply the {self.get_association_display_string(match.get_association())}."
        buffer += "</html>"
        return buffer

    def get_association_display_string(self, association):
        return f"{association.get_type()} match with source of <b>{HTMLUtilities.escape_html(association.get_source_address().toString())}</b> and destination of <b>{HTMLUtilities.escape_html(association.get_destination_address().toString())}</b>"

    def is_enabled_for_context(self, context):
        if not isinstance(context, VTMatchContext):
            return False
        match_context = VTMatchContext(context)
        matches = list(match_context.get_selected_matches())
        if len(matches) != 1:
            return False

        match = matches[0]
        association = match.get_association()
        status = association.get_status()

        return status == VTAssociationStatus.BLOCKED

    def is_add_to_popup(self, context):
        return True
