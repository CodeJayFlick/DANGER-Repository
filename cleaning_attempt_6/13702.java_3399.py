class OrcKing:
    """Orc King."""
    
    description = "This is the orc king!"

    def get_description(self):
        return self.description


# Usage example:
if __name__ == "__main__":
    orcking = OrcKing()
    print(orcking.get_description())
