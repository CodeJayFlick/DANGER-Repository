# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import object_pool as op

class OliphauntPool(op.ObjectPool):
    def create(self):
        return Oliphaunt()
