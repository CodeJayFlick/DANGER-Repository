Here is the translation of the Java code into Python:

```Python
class GotoPreviousFunctionAction:
    def __init__(self, tool):
        self.tool = tool
        
    def get_previous_function(self, program, address):
        function_iterator = program.get_listing().get_functions(address, False)
        
        if not function_iterator.has_next():
            return None
            
        next_function = function_iterator.next()
        
        while True:
            if not next_function.get_entry_point().equals(address):
                break
            if not function_iterator.has_next():
                return None
            next_function = function_iterator.next()
            
        return next_function

    def actionPerformed(self, context):
        address = context['address']
        program = context['program']
        
        function = self.get_previous_function(program, address)
        
        if function is None:
            return
            
        service = self.tool.service(GoToService())
        
        if service is not None:
            location = FunctionSignatureFieldLocation(program, 
                function.entry_point(), None, 0, function.prototype_string(False, False))
            
            navigatable = context['navigatable']
            service.go_to(navigatable, location, program)
        else:
            self.tool.status_info("Can't find Go To Service!")
```

Please note that Python does not have direct equivalent of Java's `MenuData`, `KeyBindingData` and other classes. These need to be implemented manually in the context of your application or GUI framework you are using (like Tkinter, PyQt etc.).