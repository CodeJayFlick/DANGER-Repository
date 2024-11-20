from abc import ABCMeta, abstractmethod
import concurrent.futures as futures

class DbgModelTargetBreakpointSpec(metaclass=ABCMeta):
    def __init__(self):
        self.breakpoint_info = None
        self.model_target_bpt_helper = None

    BPT_ACCESS_ATTRIBUTE_NAME = "Access"
    BPT_DISP_ATTRIBUTE_NAME = "Disposition"
    BPT_PENDING_ATTRIBUTE_NAME = "Pending"
    BPT_TIMES_ATTRIBUTE_NAME = "Times"
    BPT_TYPE_ATTRIBUTE_NAME = "Type"
    BPT_INDEX_ATTRIBUTE_NAME = "Id"

    def delete(self):
        return self.model_target_bpt_helper.delete_breakpoints(self.breakpoint_info.get_number())

    def disable(self):
        self.set_enabled(False, "Disabled")
        return self.model_target_bpt_helper.disable_breakpoints(self.breakpoint_info.get_number())

    def enable(self):
        self.set_enabled(True, "Enabled")
        return self.model_target_bpt_helper.enable_breakpoints(self.breakpoint_info.get_number())

    def get_expression(self):
        return self.breakpoint_info.get_expression()

    def get_number(self):
        return self.breakpoint_info.get_number()

    def get_kinds(self):
        if self.breakpoint_info.get_type() == "BREAKPOINT":
            return [TargetBreakpointKind.SW_EXECUTE]
        elif self.breakpoint_info.get_type() == "HW_BREAKPOINT":
            return [TargetBreakpointKind.HW_EXECUTE]
        elif self.breakpoint_info.get_type() == "HW_WATCHPOINT":
            return [TargetBreakpointKind.WRITE]
        elif self.breakpoint_info.get_type() == "READ_WATCHPOINT":
            return [TargetBreakpointKind.READ]
        elif self.breakpoint_info.get_type() == "ACCESS_WATCHPOINT":
            return [TargetBreakpointKind.READ, TargetBreakpointKind.WRITE]
        else:
            return []

    def init(self, map):
        address_space = self.model_target_bpt_helper.get_address_space("ram")
        request_native_attributes().then_accept(attrs -> {
            if attrs is not None:
                map.put_all(attrs)
                target_object_addr = attrs["Address"]
                target_object_id = attrs["Id"]
                #target_object_unique = attrs["UniqueID"]
                target_object_enabled = attrs["IsEnabled"]

                addstr = addr.get_cached_attribute("Value").toString()
                idstr = id.get_cached_attribute("Value").toString()
                set_breakpoint_id(idstr)
                #uidstr = unique.get_cached_attribute("Value").toString()

                enstr = enabled.get_cached_attribute("Value").toString()
                try:
                    address = address_space.get_address(addstr)
                    map.put("Address", address)
                except AddressFormatException as e:
                    e.printStackTrace()

                map.put("Spec", self)
                map.put("Expression", addstr)
                map.put("Kinds", get_kinds())
                #map.put(BPT_INDEX_ATTRIBUTE_NAME, Long.decode(idstr))
                map.put("Enabled", enstr == "-1")
                set_enabled(enstr == "-1", "Refreshed")

                size = self.breakpoint_info.get_size()
                map.put("Length", size)

                oldval = get_cached_attribute("Display").toString()
                display = "[" + idstr + "] " + addstr
                map.put("Display", display)
                set_modified(map, not display == oldval)
        })

    def or_zero(self, l):
        if l is None:
            return 0
        return l

    def do_get_address(self):
        breakpoint_info = self.breakpoint_info
        return self.model_target_bpt_helper.get_address("ram", self.or_zero(breakpoint_info.get_offset()))

    def update_info(self, old_info, new_info, reason):
        with lock:
            assert old_info == self.breakpoint_info
            set_breakpoint_info(new_info)
        set_enabled(new_info.is_enabled(), reason)

    def set_enabled(self, enabled, reason):
        set_breakpoint_enabled(enabled)
        change_attributes([], {"Enabled": enabled}, reason)

    @abstractmethod
    def is_enabled(self):
        pass

    def add_action(self, action):
        self.actions.add(action)

    def remove_action(self, action):
        self.actions.remove(action)

    def breakpoint_hit(self):
        target_thread = getParentProcess().get_threads().get_target_thread(getManager().get_event_thread())
        self.actions.fire.breakpoint_hit((self), target_thread, None, self)
