# Copyright (C) [2023] Peter Güttinger, SkriptLang team and contributors
#
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Skript is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Skript. If not, see <http://www.gnu.org/licenses/>.

import enum

class DamageCause(enum.Enum):
    pass  # define your damage causes here (e.g., "FALL", "PROJECTILE", etc.)

def parse(s: str) -> 'DamageCause':
    return DamageCause[s]

def to_string(dc: DamageCause, flags: int) -> str:
    return dc.name

def get_all_names() -> str:
    return ', '.join([str(damage_cause.value) for damage_cause in DamageCause])
