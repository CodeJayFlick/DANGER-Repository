class LldbModelTargetWatchpointSpecImpl:
    def __init__(self, breakpoints: 'LldbModelTargetBreakpointContainer', info):
        super().__init__(breakpoints, info, "WatchpointSpec")

    @property
    def locs(self) -> list['LldbModelTargetBreakpointLocation']:
        return self._locs

    @locs.setter
    def locs(self, value: list['LldbModelTargetBreakpointLocation']):
        self._locs = value

    def get_description(self, level):
        stream = SBStream()
        wpt = self.get_model_object()
        detail = DescriptionLevel(level)
        wpt.GetDescription(stream, detail)
        data = stream.GetData()
        return "No value" if data == "No value" else data

    def compute_kinds(self, from_obj) -> 'TargetBreakpointKindSet':
        return TargetBreakpointKindSet([TargetBreakpointKind.READ, TargetBreakpointKind.WRITE])

    def update_info(self, info: object, reason):
        if not self.valid:
            return
        self.set_model_object(info)
        self.update_attributes_from_info(reason)

        wpt = self.get_model_object()
        self.locs.append(LldbModelTargetBreakpointLocationImpl(self, wpt))
        self.set_elements(self.locs, {}, "Refreshed")

    def update_attributes_from_info(self, reason):
        wpt = self.get_model_object()
        self.change_attributes([], [], {"DISPLAY_ATTRIBUTE_NAME": self.get_description(0),
                                          "KINDS_ATTRIBUTE_NAME": self.compute_kinds(wpt),
                                          "ENABLED_ATTRIBUTE_NAME": wpt.IsEnabled(),
                                          "EXPRESSION_ATTRIBUTE_NAME": "",
                                         }, reason)
        self.change_attributes([], [], {"BPT_TYPE_ATTRIBUTE_NAME": "Hardware",
                                          "BPT_DISP_ATTRIBUTE_NAME": wpt.IsEnabled(),
                                          "BPT_VALID_ATTRIBUTE_NAME": wpt.IsValid(),
                                          "BPT_TIMES_ATTRIBUTE_NAME": wpt.GetHitCount()}, reason)

    def find_location(self, object: object) -> 'LldbModelTargetBreakpointLocation':
        return self.locs[0]
