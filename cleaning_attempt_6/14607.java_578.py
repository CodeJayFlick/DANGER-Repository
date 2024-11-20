# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import pytest

class CatalogOfFixturesGlue:
    @pytest.fixture(autouse=True)
    def integration_fixtures(self):
        yield from RecreateSimpleObjects().install()

def recreate_simple_objects():
    # implement the logic to install and return a fixture of SimpleObjects
    pass
