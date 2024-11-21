# Copyright Andreas Schildbach or authors.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import os

class PreferenceActivity:
    def on_build_headers(self, target):
        self.load_headers_from_resource('preference_headers', target)

    def on_option_selected_item(self, item):
        if item.get_id() == 'home':
            self.on_back_pressed()
            return True
        return super().on_option_selected_item(item)

    def is_valid_fragment(self, fragment_name):
        return (fragment_name == SettingsFragment.__name__ or 
                fragment_name == DiagnosticsFragment.__name__ or 
                fragment_name == AboutFragment.__name__)

class Header:
    pass

class MenuItem:
    def get_id(self):
        pass

class R:
    xml = {'preference_headers': ''}

def load_headers_from_resource(resource, target):
    # implementation missing
    pass

def on_back_pressed():
    # implementation missing
    pass

# These are classes that don't exist in Python without some kind of wrapper.
class SettingsFragment:
    __name__ = 'SettingsFragment'

class DiagnosticsFragment:
    __name__ = 'DiagnosticsFragment'

class AboutFragment:
    __name__ = 'AboutFragment'
