class PrimaryDecompilerProvider:
    def __init__(self, plugin):
        super().__init__(plugin, True)

    def is_connected(self) -> bool:
        return True
