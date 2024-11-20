class AuthenticationEnabledProfile:
    AUTH_CONFIG_OVERRIDES = {
        "nessie.server.authentication.enabled": "true"
    }

    SECURITY_CONFIG = {
        "quarkus.security.users.embedded.enabled": "true",
        "quarkus.security.users.embedded.plain-text": "true",
        "quarkus.security.users.embedded.users.admin_user": "test123",
        "quarkus.security.users.embedded.users.test_user": "test_ user",
        "quarkus.security.users.embedded.roles.admin_user": "admin, user",
        "quarkus.security.users.embedded.roles.test_user": "test123"
    }

    def get_config_overrides(self):
        return {**BaseConfigProfile.CONFIG_OVERRIDES, **self.AUTH_CONFIG_OVERRIDES, **self.SECURITY_CONFIG}
