import io

class DBDomainObjectSupport:
    def __init__(self, dbh, open_mode, monitor, name, time_interval, buf_size, consumer):
        self.open_mode = open_mode
        self.monitor = monitor
        super().__init__(dbh, name, time_interval, buf_size, consumer)

    def init(self) -> None:
        try:
            DependentServiceResolver.inject(self)
        except (CancelledException, IOException, VersionException) as e:
            if isinstance(e, VersionException):
                raise e
            elif isinstance(e, CancelledException):
                raise e
            elif isinstance(e, IOException):
                raise e
            else:
                raise AssertionError(str(e))
        finally:
            self.version_exc = None

    def finished_creating_managers(self) -> None:
        # Extension point
        pass

    def create_manager(self, manager_name: str, supplier: callable) -> object:
        try:
            return supplier(open_mode, monitor)
        except VersionException as e:
            if self.version_exc is not None:
                self.version_exc = self.version_exc.combine(e)
            else:
                raise
