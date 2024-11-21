# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

class TemperatureExpression:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Temperature"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return "Temperature at given block."

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def examples(self):
        return ["message \"%temperature of the targeted block%\""]

    @examples.setter
    def examples(self, value):
        self._examples = value

    @property
    def since(self):
        return "2.2-dev35"

    @since.setter
    def since(self, value):
        self._since = value

    def convert(self, block):
        return block.get_temperature()

    def get_property_name(self):
        return "temperature"

    def get_return_type(self):
        from numbers import Number
        return Number


# Register the expression with its class and parameters.
TemperatureExpression.register(TemperatureExpression, 'temperature[es]', 'blocks')

