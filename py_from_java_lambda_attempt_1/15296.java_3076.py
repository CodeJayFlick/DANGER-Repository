Here is the translation of the Java code to Python:

```
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
```

Please note that Python does not have direct equivalents for Android-specific classes like `View`, `TextView`, and `RecyclerView`. Also, the concept of a "view holder" in Android is different from what you would typically do in Python.