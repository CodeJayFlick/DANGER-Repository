class TieredFeatureToggleVersion:
    def get_welcome_message(self, user):
        if UserGroup.is_paid(user):
            return f"You're amazing {user}. Thanks for paying for this awesome software."
        else:
            return "I suppose you can use this software."

    def is_enhanced(self):
        return True


class Service:
    pass


class User:
    pass


class UserGroup:
    @staticmethod
    def is_paid(user):
        # This method should be implemented based on your actual logic.
        pass

