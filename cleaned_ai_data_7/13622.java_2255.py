import socket
import threading

class SymbolLookupInitializer:
    server_socket = None

    def init(first_time_consent):
        if first_time_consent:
            GhidraSymbolLookupPreferences.set_symbol_lookup_enabled(True)
        listen(GhidraSymbolLookupPreferences.get_symbol_lookup_port())

    def listen(port):
        if not GhidraSymbolLookupPreferences.is_symbol_lookup_enabled():
            print("Symbol Lookup port listening is disabled in preferences.")
            return

        if port == -1:
            print("Symbol Lookup port listening is disabled, port not set in preferences.")
            return

        try:
            global server_socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind(('localhost', port))
            server_socket.listen(5)
            print(f"Symbol Lookup is listening on port {port}")
            threading.Thread(target=socket_setup, args=(server_socket,)).start()
        except Exception as e:
            print("Failed to listen for connections on port {}. The Symbol Lookup features will be disabled until a valid port is selected in preferences.".format(port))
            return

    def socket_setup(server_socket):
        while True:
            client_socket, address = server_socket.accept()
            # Handle the connection here
            client_socket.close()

    @staticmethod
    def preferences_changed(enabled_was_changed, port_was_changed):
        if not enabled_was_changed and not port_was_changed:
            return

        try:
            if server_socket is not None:
                server_socket.close()
                print("Closed old server socket.")
        except Exception as e:
            pass  # Oh well, we tried. This port probably won't work next time they pick it.

        listen(GhidraSymbolLookupPreferences.get_symbol_lookup_port())
