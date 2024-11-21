import ghidra.app.script.GhidraScript
from ghidra.program.model.listing import Function

class IterateFunctionsScript(GhidraScript):
    def run(self):
        forward = self.askYesNo("Iterate Functions", "Do you want to iterate from low address to high address?")

        if forward:
            self.iterate_forward()
        else:
            self.iterate_backward()

    def iterate_forward(self):
        function = self.get_first_function()
        count = 0
        while True:
            if self.monitor.is_cancelled():
                break

            if function is None:
                break

            string = f"{count}   :   {function.name}  @ {function.entry_point}"
            self.monitor.set_message(string)
            print(string)

            function = self.get_function_after(function)
            count += 1
        print(f"found forward = {count}")

    def iterate_backward(self):
        function = self.get_last_function()
        count = 0
        while True:
            if self.monitor.is_cancelled():
                break

            if function is None:
                break

            string = f"{count}   :   {function.name}  @ {function.entry_point}"
            self.monitor.set_message(string)
            print(string)

            function = self.get_function_before(function)
            count += 1
        print(f"found forward = {count}")

    def get_first_function(self):
        # implement this method to return the first function in the program

    def get_last_function(self):
        # implement this method to return the last function in the program

    def get_function_after(self, function):
        # implement this method to return the next function after the given one

    def get_function_before(self, function):
        # implement this method to return the previous function before the given one
