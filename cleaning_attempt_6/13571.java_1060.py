import os
from tkinter import messagebox as tk_messagebox
from threading import Thread

class GhidraDevStartup:
    def __init__(self):
        self.first_time_consent = False

    def early_startup(self):
        job_thread = Thread(target=self.run_job)
        job_thread.start()

    def run_job(self):
        if not self.requested_open_ports():
            consent = tk_messagebox.askyesno("User Consent", 
                "This plugin opens ports to enable communication with Ghidra for various features.\n"
                "Do you consent to the ports being opened?")
            if consent:
                self.set_open_port_consent_request(True)
        else:
            first_time_consent = True

        ScriptEditorInitializer.init(first_time_consent)
        SymbolLookupInitializer.init(first_time_consent)

    def requested_conscent_to_open_ports(self):
        return GhidraRootPreferences.get().get('open_port_consent', False)

    def set_open_port_consent_request(self, value):
        GhidraRootPreferences.get()['open_port_consent'] = value

# Usage
startup = GhidraDevStartup()
startup.early_startup()

