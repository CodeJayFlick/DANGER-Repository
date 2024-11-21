class KickEffect:
    def __init__(self):
        self.players = None
        self.reason = None

    @staticmethod
    def register_effect():
        Skript.register_effect(KickEffect, "kick %players% [(by reason of|because [of]|on account of|due to) %-string%]")

    def init(self, exprs):
        if len(exprs) != 2:
            return False

        self.players = exprs[0]
        self.reason = exprs[1]

        return True

    def __str__(self):
        if not hasattr(self, 'reason') or self.reason is None:
            return "kick %players%"
        else:
            return f"kick {self.players} on account of {self.reason}"

    def execute(self, event):
        reason = self.reason.get(event) if self.reason else ""
        for player in self.players.get_array(event):
            if isinstance(event, PlayerLoginEvent) and player == event.player and not Delay.is_delayed(event):
                ((PlayerLoginEvent)event).disallow(PlayerLoginEvent.Result.KICK_OTHER, reason)
            elif isinstance(event, PlayerKickEvent) and player == event.player and not Delay.is_delayed(event):
                ((PlayerKickEvent)event).set_leave_message(reason)
            else:
                player.kick_player(reason)

class Skript:
    @staticmethod
    def register_effect(effect_class, pattern):
        pass

class Expression:
    def get_array(self, event):
        return []

    def get_single(self, event):
        return None


# Usage example:

kick = KickEffect()
Skript.register_effect(kick.__class__, "kick %players% [(by reason of|because [of]|on account of|due to) %-string%]")

def main():
    kick.init(["player1", "reason"])
    event = PlayerLoginEvent()  # Replace with actual event
    kick.execute(event)

if __name__ == "__main__":
    main()
