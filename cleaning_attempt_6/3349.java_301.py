import tkinter as tk
from tkinter import messagebox
from threading import Thread

class MergeManagerProvider:
    def __init__(self, plugin, title):
        self.plugin = plugin
        self.title = title
        self.current_component = None
        self.name_label = None
        self.card_layout = None
        self.conflict_panel = None
        self.phase_progress_panel = None
        self.apply_button = None
        self.cancel_button = None
        self.was_canceled = False

    def get_component(self):
        return self.main_panel

    def action_context(self, event):
        if isinstance(event.source, FieldHeaderComp):
            comp = event.source
            field_header_location = comp.get_field_header_location(event.point)
            return self.create_context(field_header_location)

        merge_manager = self.plugin.get_merge_manager()
        if isinstance(merge_manager, ProgramMultiUserMergeManager):
            navigatable = merge_manager.navigatable
            if isinstance(self.current_component, ListingMergePanel):
                listing_merge_panel = self.current_component
                action_context = listing_merge_panel.get_action_context(event)
                return ListingActionContext(self, navigatable, action_context)

        program_location = navigatable.location
        return ListingActionContext(self, navigatable, program_location)

    def set_apply_enabled(self, state):
        if self.apply_button:
            self.apply_button.config(state='normal' if state else 'disabled')

    def set_merge_component(self, component, component_id):
        if self.current_component is not None:
            self.card_layout.remove_widget(self.current_component)
        self.current_component = component
        self.conflict_panel.add(component, component_id)
        self.card_layout.show(self.conflict_panel, component_id)

    def remove_merge_component(self, component):
        self.card_layout.remove_widget(component)
        self.conflict_panel.remove(component)

    def update_merge_description(self, description):
        if self.name_label:
            self.name_label.config(text=description)

    def show_default_component(self):
        self.card_layout.show(self.conflict_panel, 'Default Panel')

    def dispose(self):
        self.plugin.get_tool().show_component_provider(self, False)
        self.plugin.get_tool().remove_component_provider(self)

    @property
    def merge_was_canceled(self):
        return self.was_canceled

    def apply_callback(self):
        if self.apply_button:
            self.apply_button.config(state='disabled')
        self.plugin.get_merge_manager().apply()

    def cancel_callback(self, force=False):
        choice = messagebox.askyesno('Confirm Cancel Merge', 'Warning!  Cancel causes the entire merge process to be canceled.\n' + 
                                      'Do you want to cancel the Merge Process?')

        if not force and choice:
            self.was_canceled = True
            self.plugin.get_merge_manager().cancel()

    def create(self):
        self.main_panel = tk.Frame()
        self.card_layout = tk.Toplevel()
        self.conflict_panel = tk.Frame(self.card_layout)
        self.name_label = tk.Label(text='Merge Programs', justify=tk.LEFT)

        icon_panel = tk.Frame()
        icon_panel.pack(side=tk.TOP, fill=tk.X)
        new_icon_label = tk.Label(icon_panel, image=self.MERGE_ICON)
        new_icon_label.pack(side=tk.LEFT, padx=5)
        name_label.pack(side=tk.LEFT, padx=5)

        self.main_panel.pack(fill='both', expand=True)
        self.card_layout.pack(fill='both', expand=True)
        self.conflict_panel.pack(fill='both', expand=True)

    def create_button_panel(self):
        apply_button = tk.Button(text='Apply')
        apply_button.config(command=self.apply_callback, state=tk.DISABLED)
        apply_button.tooltip('Apply conflict resolution')

        cancel_button = tk.Button(text='Cancel')
        cancel_button.config(command=lambda: self.cancel_callback(False))

        panel = tk.Frame()
        panel.pack(fill='x', padx=5)

    def create_default_panel(self):
        default_panel = tk.Frame()
        default_panel.name = 'Default Panel'

        progress_panel = self.plugin.get_merge_manager().get_merge_progress_panel()
        phase_progress_panel = tk.Label(text='Progress In Current Phase')

        default_panel.add(progress_panel)
        default_panel.add(tk.Label())
        default_panel.add(phase_progress_panel)

    def set_current_progress(self, current_percent_progress):
        if self.phase_progress_panel:
            self.phase_progress_panel.config(text=str(current_percent_progress) + '%')

    def update_progress_title(self, new_title):
        if self.phase_progress_panel:
            self.phase_progress_panel.config(text=new_title)

    def update_progress_details(self, message):
        if self.phase_progress_panel and message is not None:
            self.phase_progress_panel.config(text=message)
