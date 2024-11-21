class IsBanned:
    def __init__(self):
        self.ip_banned = None

    @staticmethod
    def register_condition():
        pass  # This method should be implemented to register the condition with Skript.

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if len(exprs) > 0:
            self.expr = exprs[0]
        self.negated = matched_pattern >= 2
        self.ip_banned = matched_pattern % 2 != 0
        return True

    def check(self, obj):
        if isinstance(obj, Player):
            if self.ip_banned:
                sock_addr = obj.get_address()
                if sock_addr is None:  # Assume not banned, they've never played here
                    return False
                return Bukkit.get_ip_bans().contains(sock_addr.get_host_address())
            else:
                return obj.is_banned()

        elif isinstance(obj, OfflinePlayer):
            return obj.is_banned()

        elif isinstance(obj, str):
            if self.ip_banned:
                return Bukkit.get_ip_bans().contains(obj)
            else:
                return any(off_player != None and off_player.name == obj for off_player in Bukkit.get_banned_players())

    def get_property_name(self):
        return "IP-banned" if self.ip_banned else "banned"
