Here is the translation of the Java code into Python:

```Python
class SourceCodeLookupPlugin:
    def __init__(self):
        self.ACTION_NAME = "Go To Symbol Source"
        self.CDT_START = "org.eclipse.cdt.core_"

    def dispose(self):
        pass  # No equivalent in Python

    def init(self):
        lookup_source_code_action = DockingAction("Source Code Lookup", self.get_name())
        lookup_source_code_action.set_enabled_for_context = lambda context: isinstance(context, ProgramLocationActionContext)
        lookup_source_code_action.action_performed = self.lookup_symbol
        tool.add_action(lookup_source_code_action)

    def lookup_symbol(self):
        symbol_text = self.get_symbol_text()
        if not symbol_text:
            return

        demangled = self.attempt_to_demangle(symbol_text)
        if demangled:
            symbol_text = demangled

        service = tool.get_service(EclipseIntegrationService)
        options = service.get_eclipse_integration_options()
        port = options.get_int(EclipseIntegrationOptionsPlugin.SYMBOL_LOOKUP_PORT_OPTION, -1)

        while True:
            connection = service.connect_to_eclipse(port)
            client_socket = connection.get_socket()

            if not client_socket:
                self.handle_unable_to_connect(connection)
                return

            try:
                with BufferedReader(InputStreamReader(client_socket.getInputStream())) as input_stream:
                    output_stream = PrintStream(client_socket.getOutputStream())
                    output_stream.print(symbol_text + "\n")
                    output_stream.flush()
                    reply = input_stream.readline().strip()

                    if symbol_text.startswith("_"):
                        symbol_text = symbol_text[1:]
                    else:
                        break

            except IOException as e:
                # shouldn't happen
                print("Unexpected exception connecting to source lookup editor", e)

            finally:
                try:
                    client_socket.close()
                except IOException as e:
                    pass  # Nothing to do

    def get_symbol_text(self):
        if isinstance(current_location, DecompilerLocation):
            decompiler_location = current_location
            token = decompiler_location.get_token()

            if not token:
                return None

            if isinstance(token, (ClangFieldToken, ClangFuncNameToken, ClangLabelToken, ClangTypeToken)):
                return token.get_text()
        else:
            location_descriptor = ReferenceUtils.get_location_descriptor(current_location)
            if not location_descriptor:
                return None
            return get_symbol_text_from_location(location_descriptor)

    def attempt_to_demangle(self, name_to_demangle):
        if not name_to_demangle:
            return None

        demangled_object = DemanglerUtil.demangle(name_to_demangle)
        if demangled_object:
            return demangled_object.get_name()
        return None

    def handle_unable_to_connect(self, connection):
        service = tool.get_service(EclipseIntegrationService)

        try:
            if not service.is_eclipse_feature_installed((lambda dir, filename: filename.startswith(self.CDT_START))):
                print("No CDT installed in Eclipse. You must install the CDT before using the source code lookup plugin.")
                return
        except FileNotFoundException as e:
            # Eclipse is not installed.
            pass

        if connection.get_process():
            print("The port used by Ghidra may not match the port used by Eclipse.\nMake sure the port in the Ghidra options (Edit -> Tool Options... -> Source Code Lookup) matches the port in the Eclipse preference page " + 
                  "(Preferences -> Ghidra -> Ghidra Symbol Lookup).")
```

Note that this is a direct translation of Java code into Python, and may not be perfect.