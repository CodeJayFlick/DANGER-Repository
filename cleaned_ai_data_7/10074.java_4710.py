import socket
import time

class InetNameLookup:
    MAX_TIME_MS = 10000
    lookup_enabled = True
    disable_on_failure = False

    def __init__(self):
        pass  # static use only

    @classmethod
    def set_disable_on_failure(cls, state):
        cls.disable_on_failure = state

    @classmethod
    def set_lookup_enabled(cls, enable):
        cls.lookup_enabled = enable

    @classmethod
    def is_enabled(cls):
        return cls.lookup_enabled

    @staticmethod
    def get_canonical_host_name(host) -> str:
        best_guess = host
        if InetNameLookup.is_enabled():
            try:
                for addr in socket.getaddrinfo(host, None)[0][4]:
                    start_time = time.time()
                    name = addr.canonicalname
                    elapsed_time = time.time() - start_time
                    if name != str(addr):
                        if host.lower() == name.lower():
                            return name  # name found matches original - use it
                        best_guess = name  # name found - update best guess
            except socket.gaierror:
                pass  # log warning and disable future lookups if necessary

        if not InetNameLookup.is_enabled():
            Msg.warn(InetNameLookup, f"Failed to resolve IP Address: {host} (Reverse DNS may not be properly configured or you may have a network problem)")
            if InetNameLookup.disable_on_failure and elapsed_time > InetNameLookup.MAX_TIME_MS:
                Msg.warn(InetNameLookup, "Reverse network name lookup has been disabled automatically due to lookup failure.")
                InetNameLookup.lookup_enabled = False

        return best_guess
