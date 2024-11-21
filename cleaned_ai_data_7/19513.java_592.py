class CustomChestInventory:
    def __init__(self):
        self.rows = None
        self.name = None

    @property
    def rows(self):
        return self._rows

    @rows.setter
    def rows(self, value):
        if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
            self._rows = value
        else:
            raise ValueError("Rows must be an integer or a string representing an integer.")

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        if isinstance(value, str):
            self._name = value
        else:
            raise ValueError("Name must be a string.")

    def get_inventory(self):
        rows = 3 if self.rows is None or not isinstance(self.rows, int) else self.rows
        name = "Chest" if self.name is None or not isinstance(self.name, str) else self.name

        size = rows * 9
        if size % 9 != 0:
            size = 27
        elif size < 0:  # Negative sizes go and crash stuff deep in NMS code
            size = 0
        elif size > 255:  # Too big values cause visual weirdness
            size = 255 * 9

        return Bukkit.create_inventory(None, size, name)

    def is_single(self):
        return True

    def get_return_type(self):
        from org.bukkit.inventory import Inventory
        return Inventory

    def __str__(self):
        if self.name:
            name_str = f" named {self.name}"
        else:
            name_str = " named \"Chest\""

        if self.rows is not None and isinstance(self.rows, int):
            rows_str = f" with {self.rows} row{'s' if self.rows > 1 else ''}"
        elif self.rows == '3':
            rows_str = " with 3 rows"
        else:
            raise ValueError("Rows must be an integer or a string representing an integer.")

        return f"chest inventory{rows_str}{name_str}"

# Register the expression
from org.bukkit import Bukkit

Bukkit.register_expression(CustomChestInventory, Inventory, 'combined', r"[a [new]] chest inventory (named|with name) %s  [with %-d row[s]]", r"[a [new]] chest inventory with %d row[s] [(named|with name) %s]")
