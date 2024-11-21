# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import enum

class InventoryAction(enum.Enum):
    # Add more actions here if needed
    pass

def parse(s: str) -> 'InventoryAction':
    return InventoryAction[s]

def get_all_names() -> list:
    return [action.name for action in InventoryAction]

def to_string(action: InventoryAction, flags: int) -> str:
    return f"{action.name} ({flags})"
