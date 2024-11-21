Here is the translation of the given Java code into Python:

```Python
class MergeTestFacilitator:
    def __init__(self):
        self.env = TestEnv()
        self.model = None

    def initialize(self, program_name: str, modifier) -> None:
        if self.model is not None:
            raise AssertionError("Initialize was called more than once!")
        
        self.model = RealProgramMTFModel(self.env)
        self.model.initialize(program_name, modifier)

    def initialize_original_program(self, program_name: str, modifier) -> None:
        if self.model is not None:
            raise AssertionError("Initialize was called more than once!")

        self.model = RealProgramMTFModel(self.env)
        self.model.initialize(program_name, modifier)

    def initialize_in_memory_program(self, program_name: str, modifier) -> None:
        if self.model is not None:
            raise AssertionError("Initialize was called more than once!")
        
        self.model = InMemoryProgramMTFModel(self.env)
        self.model.initialize(program_name, modifier)

    @staticmethod
    def copy_database_domain_file(df: 'DomainFile', new_name: str) -> 'DomainFile':
        return AbstractMTFModel.copy_database_domain_file(df, new_name)

    def get_private_change_set(self) -> 'ProgramChangeSet':
        if self.model is None:
            raise ValueError("Initialize was never called")
        
        return self.model.get_private_change_set()

    def get_result_change_set(self) -> 'ProgramChangeSet':
        if self.model is None:
            raise ValueError("Initialize was never called")

        return self.model.get_result_change_set()

    def dispose(self):
        if self.model is not None:
            self.model.dispose()
        else:
            self.env.dispose()

    @property
    def test_environment(self) -> 'TestEnv':
        return self.env

    def get_original_program(self) -> 'ProgramDB':
        if self.model is None:
            return None
        
        return self.model.get_original_program()

    def get_latest_program(self) -> 'ProgramDB':
        if self.model is None:
            return None
        
        return self.model.get_latest_program()

    def get_private_program(self) -> 'ProgramDB':
        if self.model is None:
            return None
        
        return self.model.get_private_program()

    def get_result_program(self) -> 'ProgramDB':
        if self.model is None:
            return None
        
        return self.model.get_result_program()
```

Note: The `DomainFile`, `TestEnv`, and other classes are not provided in the given Java code, so I have left them as they were. You would need to implement these classes or replace them with equivalent Python constructs for this translation to be complete.