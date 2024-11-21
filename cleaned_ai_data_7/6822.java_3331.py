import tkinter as tk
from typing import Any

class CDisplayPanel:
    def __init__(self):
        self.controller = None  # type: DecompilerController
        self.listener = None  # type: DecompileResultsListener
        self.location_listener = None  # type: ProgramLocationListener

    def set_program_location_listener(self, location_listener: Any) -> None:
        self.location_listener = location_listener

class ExtendedDecompilerController:
    def __init__(self, handler: DecompilerCallbackHandler, options: DecompileOptions, clipboard: Any):
        pass  # Not implemented in Python

    def set_decompile_data(self, decompile_data: Any) -> None:
        if self.listener is not None:
            self.listener.set_decompile_data(decompile_data)

class EmptyDecompileData:
    def __init__(self, message: str):
        self.message = message
