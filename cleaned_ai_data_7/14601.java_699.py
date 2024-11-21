# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class DomainAppFixturesProvider:
    def get_specification(self):
        return FixtureScriptsSpecification(
            multiple_execution_strategy=FixtureScripts.MultipleExecutionStrategy.EXECUTE,
            run_script_default=RecreateSimpleObjects(),
            run_script_dropdown_policy=FixtureScriptsSpecification.DropDownPolicy.CHOICES,
            recreate=RecreateSimpleObjects()
        )

class RecreateSimpleObjects:
    pass

class FixtureScriptsSpecification:
    def __init__(self, multiple_execution_strategy=None, run_script_default=None, run_script_dropdown_policy=None, recreate=None):
        self.multiple_execution_strategy = multiple_execution_strategy
        self.run_script_default = run_script_default
        self.run_script_dropdown_policy = run_script_dropdown_policy
        self.recreate = recreate

class FixtureScriptsSpecificationProvider:
    pass

# Usage example:

domain_app_fixtures_provider = DomainAppFixturesProvider()
specification = domain_app_fixtures_provider.get_specification()

print(specification)
