class InVmModelForDbgmodelProcessActivationTest:
    def get_process_pattern(self):
        return "Sessions[0x0].Processes[]"

    def model_host(self):
        return InVmDbgmodelModelHost()

    def expected_session_path(self):
        return ["Sessions[0x0]"]

    def id_from_capture(self, line):
        return f"0x{line.split()[3]}"

    def activate_via_interpreter(self, obj, interpreter):
        process_id = obj.name
        process_id = process_id[3:-1]
        output = interpreter.execute_capture("|")
        lines = output.split("\n")
        for l in lines:
            if l.contains(process_id):
                process_id = l.split()[1]
                break
        interpreter.execute(f"|{process_id} s")

class InVmDbgmodelModelHost:
    pass

# Example usage:

obj = "example_object"
interpreter = "example_interpreter"

test = InVmModelForDbgmodelProcessActivationTest()
print(test.get_process_pattern())
print(test.model_host())
print(test.expected_session_path())
print(test.id_from_capture("capture_line"))
test.activate_via_interpreter(obj, interpreter)
