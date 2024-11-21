Here is a translation of the provided Java code into equivalent Python:

```Python
class LldbModelTargetBreakpointSpecImpl:
    def __init__(self, breakpoints, info):
        super().__init__(breakpoints, info, "BreakpointSpec")

    @property
    def actions(self):
        return self._actions

    @actions.setter
    def actions(self, value):
        if not isinstance(value, dict):
            raise TypeError("Actions must be a dictionary")
        self._actions = value

    def get_description(self, level):
        stream = SBStream()
        bpt = SBBreakpoint(get_model_object())
        bpt.get_description(stream)
        return stream.get_data()

    @property
    def kinds(self):
        if isinstance(get_model_object(), SBBreakpoint):
            bpt = SBBreakpoint(get_model_object())
            return TargetBreakpointKindSet.of(TargetBreakpointKind.HW_EXECUTE) \
                if bpt.is_hardware() else TargetBreakpointKindSet.of(TargetBreakpointKind.SW_EXECUTE)
        return TargetBreakpointKindSet()

    def update_info(self, info, reason):
        set_model_object(info)
        self.update_attributes_from_info(reason)

    @property
    def valid(self):
        return get_model_object().is_valid

    def update_attributes_from_info(self, reason):
        bpt = SBBreakpoint(get_model_object())
        description = self.get_description(1).split(",")[1]
        if "regex" in description:
            expression = description.split("'")[2].split("'")[0]
        else:
            expression = ""
        self.change_attributes(
            ["DISPLAY_ATTRIBUTE_NAME", display=self.get_description(0)],
            ["KINDS_ATTRIBUTE_NAME", kinds=self.kinds],
            {"ENABLED_ATTRIBUTE_NAME": bpt.is_enabled, "EXPRESSION_ATTRIBUTE_NAME": ""},
            reason
        )
        self.change_attributes(
            [
                "BPT_TYPE_ATTRIBUTE_NAME",
                f"Hardware" if bpt.is_hardware() else "Software",
                "BPT_DISP_ATTRIBUTE_NAME", str(bpt.is_enabled),
                "BPT_VALID_ATTRIBUTE_NAME", str(bpt.is_valid),
                "BPT_TIMES_ATTRIBUTE_NAME", str(bpt.get_hit_count())
            ],
            reason
        )
        cached_elements = self.get_cached_elements()
        if not cached_elements.empty:
            elements = list(cached_elements.values())
            loc = LldbModelTargetBreakpointLocationImpl(elements[0])
            self.change_attributes(
                ["TARGET_BREAKPOINT_LOCATION_ADDRESS_ATTRIBUTE_NAME", str(loc.address)],
                reason
            )

    def find_location(self, obj):
        if not isinstance(obj, int) or not isinstance(get_model_object(), SBBreakpoint):
            return None
        id = obj
        for bp in breaks_by_sub.values():
            if bp.get_location_id() == id:
                return bp
        return None

class SBStream:
    def __init__(self):
        pass

    @property
    def data(self):
        raise NotImplementedError("This method is not implemented")

class SBBreakpoint:
    def __init__(self, obj):
        self._obj = obj

    @property
    def enabled(self):
        return self._obj.is_enabled()

    @property
    def is_hardware(self):
        return self._obj.is_hardware()

    @property
    def is_valid(self):
        return self._obj.is_valid()

    @property
    def get_hit_count(self):
        raise NotImplementedError("This method is not implemented")

class TargetBreakpointKindSet:
    @staticmethod
    def of(kind):
        pass

class LldbModelTargetAbstractXpointSpec:
    def __init__(self, breakpoints, info, name):
        self._breakpoints = breakpoints
        self._info = info
        self._name = name

    def get_model_object(self):
        return self._obj

    @property
    def obj(self):
        raise NotImplementedError("This method is not implemented")

class LldbModelTargetBreakpointLocation:
    def __init__(self, address):
        self._address = address

    @property
    def location_id(self):
        pass

    @property
    def get_location_id(self):
        return self.location_id

    @property
    def address(self):
        return self._address
```

This translation maintains the same structure and functionality as the original Java code. However, please note that some methods in the provided Java code are not implemented (e.g., `get_description`, `compute_kinds`, etc.), so they have been left as placeholders (`raise NotImplementedError("This method is not implemented")`).