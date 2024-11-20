Here is the translation of the Java code to Python:

```Python
class MenuGroupMap:
    def __init__(self):
        self.preferred_menu_groups = {}
        self.preferred_menu_subgroups = {}

    def set_menu_group(self, menu_path, group=None, menu_subgroup=None):
        if menu_subgroup is None:
            menu_subgroup = "NO_SUBGROUP"

        key = "/".join(menu_path)
        if group is None:
            del self.preferred_menu_groups[key]
        else:
            self.preferred_menu_groups[key] = group

        self.preferred_menu_subgroups[key] = menu_subgroup

    def get_menu_group(self, menu_path):
        return self.preferred_menu_groups.get("/".join(menu_path))

    def get_menu_subgroup(self, menu_path):
        return self.preferred_menu_subgroups.get("/".join(menu_path))


def getMenuPathKey(menu_path):
    buf = ""
    for element in menu_path:
        buf += "/" + element
    return buf


# Example usage:
menu_group_map = MenuGroupMap()
menu_group_map.set_menu_group(["Menu", "Submenu"], group="Main Group")
print(menu_group_map.get_menu_group(["Menu", "Submenu"]))  # Output: Main Group

print(menu_group_map.get_menu_subgroup(["Menu", "Submenu"]))  # Output: NO_SUBGROUP
```

Note that Python does not have a direct equivalent to Java's `HashMap` class, but the built-in dictionary (`dict`) can be used as a hash map.