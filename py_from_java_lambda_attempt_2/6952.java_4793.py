Here is the translation of the given Java code into Python:

```Python
class DecompilerParameterIDValidator:
    NAME = "Decompiler Parameter ID Validator"
    MIN_NUM_FUNCS_DEFAULT = 1
    MIN_NUM_FUNCS = f"Minimum analysis threshold ({MIN_NUM_FUNCS_DEFAULT} % of funcs)"

    def __init__(self, program):
        pass

    def do_run(self, monitor):
        threshold = self.MIN_NUM_FUNCS_DEFAULT
        status = "Passed"
        warnings = ""
        number = 0
        for func in program.get_functions():
            if func.has_signature_source(SourceType.ANALYSIS):
                number += 1
        if number < threshold:
            status = "Warning"
            warnings = f"{program.domain_file.name} - {number} functions with signatures from the decompiler parameter id analyzer\n"
        return {"status": status, "warnings": warnings}

    def check_number_analyzed(self, program):
        num_funcs_with_parameter_id = 0
        for func in program.get_functions():
            if func.has_signature_source(SourceType.ANALYSIS):
                num_funcs_with_parameter_id += 1
        return num_funcs_with_parameter_id

    def get_description(self):
        return f"Make sure at least {self.MIN_NUM_FUNCS_DEFAULT} function(s) have signatures from the decompiler parameter id analyzer"

    def get_name(self):
        return self.NAME

    def __str__(self):
        return self.get_name()
```

Please note that Python does not support static variables like Java. So, I've replaced them with class-level attributes. Also, Python's `ConditionResult` and `TaskMonitor` are not directly equivalent to their Java counterparts, so I have omitted those parts in the translation.