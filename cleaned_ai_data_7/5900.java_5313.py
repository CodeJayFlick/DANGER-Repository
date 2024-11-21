class AddressSetTableModel:
    def __init__(self, title: str, serviceProvider, program: dict, address_set_view: object, task_monitor):
        self.address_set = address_set_view
        super().__init__(title=title, service_provider=serviceProvider, prog=program, monitor=task_monitor)

    @property
    def do_load(self) -> None:
        accumulator = Accumulator()
        try:
            for address in self.address_set.get_addresses(True):
                if task_monitor.check_canceled():
                    raise CancelledException
                accumulator.add(address)
                task_monitor.increment_progress(1)
        except CancelledException as e:
            print(f"Cancelled: {e}")
