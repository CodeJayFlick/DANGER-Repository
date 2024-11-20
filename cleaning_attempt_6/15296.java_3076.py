# Copyright Andreas Schildbach or other original authors.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

class SeparatorViewHolder:
    def __init__(self):
        pass

    label = None

    # This method is equivalent to Java's constructor.
    def setup(self, itemView):
        self.label = itemView.find_element_by_id("text1")
