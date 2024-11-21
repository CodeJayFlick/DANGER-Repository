class AuthorOperator:
    def __init__(self, token_int_type: int, author_type):
        self.author_type = author_type
        # Add other attributes as needed (e.g., userName, roleName, password)

    @property
    def get_author_type(self) -> 'AuthorType':
        return self.author_type

class AuthorType:
    CREATE_USER = 0
    CREATE_ROLE = 1
    DROP_USER = 2
    DROP_ROLE = 3
    GRANT_ROLE = 4
    GRANT_USER = 5
    GRANT_ROLE_TO_USER = 6
    REVOKE_USER = 7
    REVOKE_ROLE = 8
    REVOKE_ROLE_FROM_USER = 9
    UPDATE_USER = 10
    LIST_USER = 11
    LIST_ROLE = 12
    LIST_USER_PRIVILEGE = 13
    LIST_ROLE_PRIVILEGE = 14
    LIST_USER_ROLES = 15
    LIST_ROLE_USERS = 16

    @classmethod
    def deserialize(cls, i: int) -> 'AuthorType':
        if i == AuthorOperator.CREATE_USER:
            return cls.CREATE_USER
        elif i == AuthorOperator.CREATE_ROLE:
            return cls.CREATE_ROLE
        # Add more cases as needed (e.g., DROP_*, GRANT_*, REVOKE_*)

    @classmethod
    def serialize(cls, author_type: 'AuthorType') -> int:
        if author_type == cls.CREATE_USER:
            return 0
        elif author_type == cls.CREATE_ROLE:
            return 1
        # Add more cases as needed (e.g., DROP_*, GRANT_*, REVOKE_*)

class AuthorPlan(PhysicalPlan):
    def __init__(self, 
                 author_type: 'AuthorType', 
                 user_name: str, 
                 role_name: str, 
                 password: str, 
                 new_password: str, 
                 privilege_list: list[str], 
                 node_name: PartialPath
                ):
        super().__init__()
        self.author_type = author_type
        self.user_name = user_name
        self.role_name = role_name
        self.password = password
        self.new_password = new_password
        self.privilege_list = privilege_list
        self.node_name = node_name

    # Add methods as needed (e.g., generate_physical_plan)
