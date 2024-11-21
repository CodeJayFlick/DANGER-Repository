import tkinter as tk
from gi.repository import Gtk

class ProviderToggleAction:
    def __init__(self, provider):
        self.component_provider = provider
        self.set_name(f"Show {provider.get_title()}")
        self.set_icon(provider.get_icon())
        self.set_group("ZGroup")
        
        if not hasattr(self, 'selected'):
            self.selected = True
        
        self.toolbar_data = Gtk.ToolbarData()
        self.toolbar_data.set_icon(provider.get_icon())
        self.toolbar_data.set_group("ZGroup")

    def install_visibility_tracker(self):
        component = provider.get_component()
        component.add_hierarchy_listener(
            lambda e: setattr(self, 'selected', provider.is_visible()) if (e.change_flags & HierarchyEvent.SHOWING_CHANGED) else None
        )

    def action_performed(self, context):
        self.component_provider.set_visible(getattr(self, 'selected'))
