Here is the translation of the Java interface `MarkupItemStorage` to a Python class:

```python
class MarkupItemStorage:
    def __init__(self):
        self._markup_type = None
        self._association = None
        self._source_address = None
        self._destination_address = None
        self._destination_address_source = None
        self._status = None

    @property
    def markup_type(self):
        return self._markup_type

    @markup_type.setter
    def markup_type(self, value):
        self._markup_type = value

    @property
    def association(self):
        return self._association

    @association.setter
    def association(self, value):
        self._association = value

    @property
    def source_address(self):
        return self._source_address

    @source_address.setter
    def source_address(self, value):
        self._source_address = value

    @property
    def destination_address(self):
        return self._destination_address

    @destination_address.setter
    def destination_address(self, value):
        self._destination_address = value

    @property
    def destination_address_source(self):
        return self._destination_address_source

    @destination_address_source.setter
    def destination_address_source(self, value):
        self._destination_address_source = value

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    @property
    def status_description(self):
        # assuming this is a computed property based on the status attribute
        if self.status:
            return f"Status: {self.status.name}"
        else:
            return "No status set"

    @property
    def source_value(self):
        # assuming this is a computed property that returns some value from the association or markup type
        pass

    @source_value.setter
    def source_value(self, value):
        self._association = value  # or update the association attribute accordingly

    @property
    def destination_value(self):
        # assuming this is a computed property that returns some value based on the destination address and/or status
        pass

    @destination_value.setter
    def destination_value(self, value):
        self._destination_address = value  # or update the destination address attribute accordingly

    def set_status(self, status):
        self.status = status
        return self

    def reset(self):
        self._markup_type = None
        self._association = None
        self._source_address = None
        self._destination_address = None
        self._destination_address_source = None
        self._status = None
        return self

    def set_destination_address(self, address, source):
        self.destination_address = address
        self.destination_address_source = source
        return self

    def set_apply_failed(self, message):
        # assuming this method updates the status or some other attribute based on the message
        pass

    def set_source_destination_values(self, source_value, destination_value):
        self.source_value = source_value
        self.destination_value = destination_value
```

Note that I've made some assumptions about how certain properties and methods should behave in Python. You may need to adjust these implementations based on your specific requirements.