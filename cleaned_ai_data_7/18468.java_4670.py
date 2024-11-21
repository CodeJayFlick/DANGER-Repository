class ClipPathView:
    def __init__(self):
        pass

    def draw(self, canvas=None, paint=None, opacity=0):
        print("RNSVG: ClipPath can't be drawn, it should be defined as a child component for `Defs`")

    def save_definition(self):
        # Note that there is no equivalent method in Python to defineClipPath
        pass

    def is_responsible(self):
        return False

    def hit_test(self, src=None):
        return -1

    def merge_properties(self, target=None):
        pass

    def reset_properties(self):
        pass


# Copyright (c) 2015-present, Horcrux.
# All rights reserved.

# This source code is licensed under the MIT-style license found in the
# LICENSE file in the root directory of this source tree.
