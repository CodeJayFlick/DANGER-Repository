import tkinter as tk
from tkinter import ttk
from typing import List

class VTImpliedMatchesTableProvider:
    def __init__(self, controller):
        self.controller = controller
        self.component = None
        self.implied_match_table_model = None
        self.show_reference_location_action = None
        self.show_reference_to_location_action = None
        self.filter_panel = None

    def create_component(self) -> tk.Widget:
        panel = ttk.Frame()
        table_panel = self.create_implied_match_table_panel()
        filter_panel = GhidraTableFilterPanel(implied_matches_table, implied_match_table_model)
        panel.add(table_panel, 'center')
        panel.add(filter_panel, 'south')
        return panel

    def create_actions(self):
        show_reference_location_action = ToggleDockingAction("Show Reference Locations", VTPlugin.OWNER)  # TO DO
        show_reference_to_location_action = ToggleDockingAction("Show Locations Reference", VTPlugin.OWNER)  # TO DO
        action = CreateImpliedMatchAction(controller, self)
        add_local_action(action)

    def get_component(self):
        return component

    def component_hidden(self):
        pass

    def component_shown(self):
        implied_match_table_model.session_changed()

    def markup_item_selected(self, markup_item: VTMarkupItem):  # TO DO
        pass

    def match_selected(self, match_info: MatchInfo):
        if not self.is_visible():
            return
        implied_match_table_model.reload()

    def options_changed(self, options: Options):  # TO DO
        pass

    def read_config_state(self, save_state: SaveState):  # TO DO
        pass

    def write_config_state(self, save_state: SaveState):  # TO DO
        pass

    def session_changed(self):
        if not self.is_visible():
            return
        implied_match_table_model.session_changed()

    def disposed(self):
        if implied_matches_table is None:
            return
        selection_model = implied_matches_table.selection_model()
        selection_model.remove_list_selection_listener(implied_selection_listener)
        implied_matches_table.dispose()
        implied_match_table_model.dispose()
        filter_panel.dispose()

    def session_updated(self, event: DomainObjectChangedEvent):  # TO DO
        pass

    def reload(self):
        implied_match_table_model.clear()
        implied_match_table_model.reload()

    def navigate_selected_item(self):
        if not self.is_visible():
            return
        model = (RowObjectTableModel[ImpliedMatchWrapperRowObject])implied_matches_table.model()
        selected_row = implied_matches_table.selection()[0]
        match_info = model.get_object(selected_row)
        if show_reference_location:
            controller.goto_source_location(match_info.source_reference_location())
            controller.goto_destination_location(match_info.destination_reference_location())
        else:
            source_loc = ProgramLocation(controller.source_program(), match_info.source_address())
            destination_loc = ProgramLocation(controller.destination_program(), match_info.destination_address())
            controller.goto_source_location(source_loc)
            controller.goto_destination_location(destination_loc)

    def get_selected_matches(self) -> List[VTMatch]:
        model = (RowObjectTableModel[ImpliedMatchWrapperRowObject])implied_matches_table.model()
        selected_rows = implied_matches_table.selection()[0]
        matches_list = []
        for row in selected_rows:
            object_row = model.get_object(row)
            match_info = object_row.match
            if match_info is not None:
                matches_list.append(match_info)
        return matches_list

    def get_selected_implied_matches(self) -> List[VTImpliedMatchInfo]:
        model = (RowObjectTableModel[ImpliedMatchWrapperRowObject])implied_matches_table.model()
        selected_rows = implied_matches_table.selection()[0]
        matches_list = []
        for row in selected_rows:
            object_row = model.get_object(row)
            match_info = object_row.match
            if match_info is None:
                matches_list.append(object_row)
        return matches_list

    def create_implied_match_table_panel(self) -> GThreadedTablePanel[ImpliedMatchWrapperRowObject]:
        implied_match_table_model = VTImpliedMatchesTableModel(controller)
        table_panel = GhidraThreadedTablePanel(implied_match_table_model)
        implied_matches_table = table_panel.table
        implied_selection_listener = lambda e: self.navigate_selected_item()
        selection_model = implied_matches_table.selection_model()
        selection_model.add_list_selection_listener(implied_selection_listener)

    def set_sub_title(self, title):
        pass

class GhidraTableFilterPanel:
    def __init__(self, table, model):
        self.table = table
        self.model = model

class GThreadedTablePanel:
    def __init__(self, model):
        self.table = None
        self.model = model

def main():
    controller = VTController()
    provider = VTImpliedMatchesTableProvider(controller)
    component = provider.create_component()

if __name__ == "__main__":
    main()
