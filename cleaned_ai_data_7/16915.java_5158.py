class UserManager:
    def __init__(self):
        pass  # Initialize with default values or None if needed.

    def get_user(self, username: str) -> dict:
        """Get a user object."""
        raise NotImplementedError("Method not implemented")

    def create_user(self, username: str, password: str) -> bool:
        """Create a user with given username and password. New users will only be granted no privileges."""
        raise NotImplementedError("Method not implemented")

    def delete_user(self, username: str) -> bool:
        """Delete a user."""
        raise NotImplementedError("Method not implemented")

    def grant_privilege_to_user(self, username: str, path: str, privilege_id: int) -> bool:
        """Grant a privilege on a seriesPath to a user."""
        raise NotImplementedError("Method not implemented")

    def revoke_privilege_from_user(self, username: str, path: str, privilege_id: int) -> bool:
        """Revoke a privilege on seriesPath from a user."""
        raise NotImplementedError("Method not implemented")

    def update_user_password(self, username: str, new_password: str) -> bool:
        """Modify the password of a user."""
        raise NotImplementedError("Method not implemented")

    def grant_role_to_user(self, role_name: str, username: str) -> bool:
        """Add a role to a user."""
        raise NotImplementedError("Method not implemented")

    def revoke_role_from_user(self, role_name: str, username: str) -> bool:
        """Revoke a role from a user."""
        raise NotImplementedError("Method not implemented")

    def reset(self):
        """Re-initialize this object."""
        pass  # No-op or initialize with default values if needed.

    def list_all_users(self) -> list:
        """List all users in the database."""
        return []  # Return an empty list

    def is_user_use_water_mark(self, username: str) -> bool:
        """Whether data water-mark is enabled for user 'userName'."""
        raise NotImplementedError("Method not implemented")

    def set_user_use_water_mark(self, username: str, use_water_mark: bool):
        """Enable or disable data water-mark for user 'userName'."""
        raise NotImplementedError("Method not implemented")

    def replace_all_users(self, users: dict) -> None:
        """Clear all old users info, replace the old users with the new one. The caller should guarantee that no other methods of this interface are invoked concurrently when this method is called."""
        pass  # No-op or initialize with default values if needed.
