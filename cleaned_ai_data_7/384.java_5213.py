class TestKnownArchDebuggerMappingOpinion:
    ARCH = "test-known-arch"

    def offers_for_env(self, env: str, process: str, include_overrides: bool) -> set:
        if not self.ARCH == env.get_architecture():
            return set()
        return {self.default_offer(process)}

    def default_offer(self, process: str) -> dict:
        return {
            "process": process,
            "priority": 100,
            "description": f"Offer for {self.ARCH}",
            "language_id": self.langid_toybe64(),
            "compiler_spec_id": "default",
            "overrides": set()
        }

    def langid_toybe64(self) -> str:
        return "ToyBe64"
