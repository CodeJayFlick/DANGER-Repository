Here is the translation of the Java code to Python:
```
class OffcutReferencesVTPreconditionValidator:
    def __init__(self, source_program: 'Program', destination_program: 'Program',
                 existing_results: 'VTSession'):
        super().__init__(source_program, destination_program, existing_results)

    def create_post_analysis_precondition_validator(self, program: 'Program') -> 'PostAnalysisValidator':
        return OffcutReferencesValidator(program)
```
Note that I've used type hints to indicate the expected types of the parameters and return values. This is not strictly necessary in Python 3.x, but it can be helpful for documentation purposes.

Also, since there are no specific classes or interfaces defined in Java (e.g., `VTSession`, `Program`), I've left those as-is, assuming they will be replaced with equivalent Python types or objects when the code is actually used.