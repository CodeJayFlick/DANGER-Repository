import concurrent.futures

class DbgDebugInputCallbacks:
    def __init__(self, manager):
        self.manager = manager

    def start_input(self, bufsize):
        self.manager.get_event_listeners().fire_prompt_changed(">>>")
        cf = concurrent.futures.Future()
        try:
            self.manager.set_continuation(cf)
            self.manager.get_control().return_input(cf.result())
        except (concurrent.futures.TimeoutError, concurrent.futures.CancelledError) as e:
            print(e.stacktrace())

class DbgManagerImpl:
    def __init__(self):
        pass

    def get_event_listeners(self):
        # TO DO: implement this method
        raise NotImplementedError("get_event_listeners() not implemented")

    def set_continuation(self, cf):
        # TO DO: implement this method
        raise NotImplementedError("set_continuation() not implemented")

    def get_control(self):
        # TO DO: implement this method
        raise NotImplementedError("get_control() not implemented")
