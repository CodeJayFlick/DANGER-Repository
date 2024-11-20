class Role:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    BORROWER = "Borrower"
    INVESTOR = "Investor"

    _instances = {}

    def instance(self, role_type: str) -> Optional[CustomerRole]:
        if role_type not in self._instances:
            try:
                self._instances[role_type] = getattr(CustomerRoles(), role_type)
            except (AttributeError, TypeError):
                self.logger.error("error creating an object", exc_info=True)

        return self._instances.get(role_type)


class CustomerRole:
    pass


# Usage
if __name__ == "__main__":
    role = Role()
    borrower_role = role.instance(Role.BORROWER)
    investor_role = role.instance(Role.INVESTOR)
