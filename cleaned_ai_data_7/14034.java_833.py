# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import inject

class TobaccoModule:
    def configure(self):
        self.bind(Tobacco, to=RivendellTobacco)

if __name__ == "__main__":
    pass
