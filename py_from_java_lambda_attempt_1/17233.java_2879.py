Here's your Java class translated into a Python class:

```Python
class SpecialClauseComponent:
    def __init__(self):
        self.row_limit = 0
        self.row_offset = 0
        self.series_limit = 0
        self.series_offset = 0
        self.ascending = True
        self.without_any_null = False
        self.without_all_null = False
        self.group_by_level_controller = None
        self.levels = []
        self.is_align_by_device = False
        self.is_align_by_time = True

    @property
    def row_limit(self):
        return self._row_limit

    @row_limit.setter
    def row_limit(self, value):
        self._row_limit = value

    @property
    def row_offset(self):
        return self._row_offset

    @row_offset.setter
    def row_offset(self, value):
        self._row_offset = value

    def has_limit(self):
        return self.row_limit > 0

    @property
    def series_limit(self):
        return self._series_limit

    @series_limit.setter
    def series_limit(self, value):
        self._series_limit = value

    @property
    def series_offset(self):
        return self._series_offset

    @series_offset.setter
    def series_offset(self, value):
        self._series_offset = value

    def has_slimit(self):
        return self.series_limit > 0

    def has_soffset(self):
        return self.series_offset > 0

    @property
    def ascending(self):
        return self._ascending

    @ascending.setter
    def ascending(self, value):
        self._ascending = value

    @property
    def without_any_null(self):
        return self._without_any_null

    @without_any_null.setter
    def without_any_null(self, value):
        self._without_any_null = value

    @property
    def without_all_null(self):
        return self._without_all_null

    @without_all_null.setter
    def without_all_null(self, value):
        self._without_all_null = value

    @property
    def levels(self):
        return self.__levels

    @levels.setter
    def levels(self, value):
        self.__levels = value

    def set_group_by_level_controller(self, group_by_level_controller):
        self.group_by_level_controller = group_by_level_controller

    @property
    def is_align_by_device(self):
        return self._is_align_by_device

    @is_align_by_device.setter
    def is_align_by_device(self, value):
        self._is_align_by_device = value

    @property
    def is_align_by_time(self):
        return self._is_align_by_time

    @is_align_by_time.setter
    def is_align_by_time(self, value):
        self._is_align_by_time = value
```

This Python class has the same properties and methods as your Java class. Note that I used property decorators (`@property` and `@<attribute>.setter`) to implement getter and setter methods for each attribute in a more concise way than you would with regular get and set methods.