Here is the translation of the Java code into Python:

```Python
class ModuleSortPlugin:
    SORT_BY_NAME = 1
    SORT_BY_ADDRESS = 2

    def __init__(self):
        self.sort_by_addr_action = None
        self.sort_by_name_action = None

    def create_actions(self, tool):
        self.sort_by_addr_action = ModuleSortAction("Sort Fragments By Address", "Module Sort Plugin", self.SORT_BY_ADDRESS)
        self.sort_by_name_action = ModuleSortAction("Sort Fragments By Name", "Module Sort Plugin", self.SORT_BY_NAME)

        tool.add_action(self.sort_by_addr_action)
        tool.add_action(self.sort_by_name_action)

    def module_sort_callback(self, sort_type, context_obj):
        if isinstance(context_obj, ProgramNode) and context_obj.is_module() and context_obj.get_tree().get_selection_count() == 1:
            return self.do_sort(context_obj.module(), GroupComparator(sort_type), None)
        else:
            return

    def do_sort(self, parent, comparator, monitor=None):
        list = []
        kids = parent.get_children()

        if monitor is not None:
            monitor.initialize(len(kids))

        for kid in kids:
            if isinstance(kid, ProgramNode) and kid.is_module():
                self.do_sort(kid.module(), comparator, monitor)
            else:
                list.append(kid)

            if monitor is not None:
                monitor.check_cancelled()
                monitor.increment_progress(1)

        list.sort(comparator)

        if monitor is not None:
            monitor.initialize(len(list))
            for i in range(len(list)):
                if isinstance(list[i], ProgramNode) and list[i].is_module():
                    parent.move_child(list[i].name(), i)
                else:
                    parent.move_child(list[i].name(), i)

                if i % 10 == 0:
                    allow_swing_thread_to_paint_between_long_locking()

    def allow_swing_thread_to_paint_between_long_locking(self):
        try:
            time.sleep(100)
        except Exception as e:
            pass

    def get_selected_module(self, context_obj):
        if isinstance(context_obj, ProgramNode) and context_obj.is_module() and context_obj.get_tree().get_selection_count() == 1:
            return context_obj.module()
        else:
            return None


class SortTask(Task):
    def __init__(self, module, sort_type):
        super().__init__("Sort " + (" by Address" if sort_type == ModuleSortPlugin.SORT_BY_ADDRESS else " by Name"), True, True, True)
        self.module = module
        self.comparator = GroupComparator(sort_type)

    def run(self, monitor=None):
        tx_id = -1
        success = False

        try:
            tx_id = current_program.start_transaction("Sort")
            self.do_sort(self.module, self.comparator, None)
            success = True
        except CancelledException as e:
            pass
        except Exception as e:
            Msg.show_error(None, "Error", "Module Sort Failed", e)

        finally:
            if tx_id != -1 and not success:
                current_program.end_transaction(tx_id, False)


class GroupComparator:
    def __init__(self, sort_type):
        self.sort_type = sort_type

    def compare(self, g1, g2):
        if self.sort_type == ModuleSortPlugin.SORT_BY_ADDRESS:
            addr1 = None
            addr2 = None

            if isinstance(g1, ProgramFragment):
                addr1 = g1.get_min_address()
            else:
                m = g1.module()
                addr1 = m.address_set().get_min_address()

            if isinstance(g2, ProgramFragment):
                addr2 = g2.get_min_address()
            else:
                m = g2.module()
                addr2 = m.address_set().get_min_address()

            if addr1 is None and addr2 is None:
                return 0
            elif addr1 is not None and addr2 is None:
                return -1
            elif addr1 is None:
                return 1

            return addr1.compare_to(addr2)
        else:
            return g1.name().compare(g2.name())


class ModuleSortAction(DockingAction):
    def __init__(self, name, owner, sort_type):
        super().__init__(name, owner)

        self.sort_type = sort_type
        if sort_type == ModuleSortPlugin.SORT_BY_ADDRESS:
            self.set_popup_menu_data(MenuData(SORT_BY_ADDR_MENUPATH, None, "module"))
            self.description = f"Perform a minimum address sort of all fragments contained within a selected folder"
        else:
            self.set_popup_menu_data(MenuData(SORT_BY_NAME_MENUPATH, None, "module"))

            self.description = f"Perform a name sort of all fragments contained within a selected folder"

        self.enabled = True  # always enabled
        self.help_location = HelpLocation("ProgramTreePlugin", "SortByAddressOrName")

    def is_enabled_for_context(self, context):
        active_obj = context.get_context_object()

        if isinstance(active_obj, ProgramNode) and active_obj.is_module() and context.get_tree().get_selection_count() == 1:
            return True
        else:
            return False

    def action_performed(self, context):
        self.module_sort_callback(self.sort_type, context.get_context_object())
```

Please note that Python does not support Java's `@formatter:off` and `@formatter:on`, so I have removed them. Also, the translation is based on my understanding of the code, but it may require some adjustments to work correctly in a Python environment.