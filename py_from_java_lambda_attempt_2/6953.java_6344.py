Here is the translation of the given Java code into Python:

```Python
class DecompilerValidator:
    NAME = "Decompiler Validator"

    def __init__(self, program):
        pass  # equivalent to super(program)

    def do_run(self, monitor):
        listing = program.get_listing()
        iter = listing.get_functions(True)
        functions = self.filter_functions(program, iter, monitor)

        callback = DecompilerCallback(program, DecompilerValidatorConfigurer())
        try:
            results = ParallelDecompiler.decompile_functions(callback, functions, monitor)
            return self.process_results(results)
        except Exception as e:
            Msg.error(self, "Unexpected Exception validating functions", e)
        finally:
            callback.dispose()

        return ConditionResult(ConditionStatus.Error, "Unable to validate functions (see log)")

    def filter_functions(self, program, iter, monitor):
        results = []
        listing = program.get_listing()
        while iter.has_next():
            f = iter.next()
            if monitor.is_cancelled():
                return []

            entry_point = f.entry_point
            code_unit_at = listing.code_unit_at(entry_point)
            if code_unit_at is None:
                continue

            if isinstance(code_unit_at, Instruction):
                results.append(f)

        return results

    def process_results(self, results):
        status = ConditionStatus.Passed
        warnings = ""
        for result in results:
            if result is None:
                continue

            status = ConditionStatus.Warning
            warnings += str(result) + "\n"

        return ConditionResult(status, warnings)


class DecompilerCallback:
    def __init__(self, program, configurer):
        self.program = program
        self.configurer = configurer

    def process(self, results, monitor):
        f = results.get_function()
        error_message = results.get_error_message()
        if not str(error_message).strip():
            return None

        return "{} ({}) : {}".format(f.name, f.entry_point, error_message)


class DecompilerValidatorConfigurer:
    def configure(self, decompiler):
        options = self.get_deompiler_options()
        decompiler.set_options(options)
        decompiler.open_program()


def get_deompiler_options(self):
    try:
        spec = program.compiler_spec
        model = spec.prototype_evaluation_model(EvaluationModelType.EVAL_CURRENT)
        return DecompilerOptions(model.name)

    except Exception as e:
        Msg.warn(self, "problem setting prototype evaluation model: {}".format(e.message))
```

Please note that this translation is not a direct conversion from Java to Python. It's more of an interpretation based on the given code and might require some adjustments according to your specific use case.

Here are some notes about the translation:

- The `DecompilerCallback` class in Java has been split into two classes (`DecompilerCallback` and `DecompilerValidatorConfigurer`) as they seem to be related but have different responsibilities.
- In Python, we don't need a separate constructor for each class. We can define methods directly inside the class definition.
- Some exceptions are not explicitly handled in this translation (like `Exception e`). You might want to add specific exception handling based on your requirements.
- The code is structured similarly as it was in Java but with Python's syntax and conventions.