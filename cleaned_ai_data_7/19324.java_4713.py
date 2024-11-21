import datetime

class EffBan:
    def __init__(self):
        self.players = None
        self.reason = None
        self.expires = None
        self.ban = False
        self.ip_ban = False

    @staticmethod
    def register_effect():
        pass  # This is equivalent to the static block in Java, but it's not necessary in Python.

    def init(self, exprs, matched_pattern):
        if len(exprs) > 0:
            self.players = exprs[0]
        if len(exprs) > 1:
            self.reason = str(exprs[1])
        if len(exprs) > 2:
            self.expires = Timespan(str(exprs[2]))
        self.ban = matched_pattern % 2 == 0
        self.ip_ban = matched_pattern >= 2

    def execute(self, e):
        reason = self.reason if self.reason else None
        expires = self.expires.get_single(e) if self.expires else None
        source = "Skript ban effect"
        for player in self.players:
            if isinstance(player, str):  # IP address or offline player name
                if self.ip_ban:
                    ip_address = InetSocketAddress(InetAddress(gethostbyname(player)), 0)
                    if not ip_address.getHostName():
                        return  # Can't ban unknown IP
                    Bukkit.getBanList(BanList.Type.IP).addBan(ip_address.getHostAddress(), reason, expires, source) if self.ban else Bukkit.getBanList(BanList.Type.IP).pardon(ip_address.getHostAddress())
                elif isinstance(player, OfflinePlayer):
                    name = player.getName()
                    if not name:
                        return  # Can't ban, name unknown
                    Bukkit.getBanList(BanList.Type.NAME).addBan(name, reason, expires, source) if self.ban else Bukkit.getBanList(BanList.Type.NAME).pardon(name)
            elif isinstance(player, Player):
                if self.ip_ban:
                    ip_address = InetSocketAddress(InetAddress(gethostbyname(str(player))), 0)
                    if not ip_address.getHostName():
                        return  # Can't ban unknown IP
                    Bukkit.getBanList(BanList.Type.IP).addBan(ip_address.getHostAddress(), reason, expires, source) if self.ban else Bukkit.getBanList(BanList.Type.IP).pardon(ip_address.getHostAddress())
                elif isinstance(player, OfflinePlayer):
                    name = player.getName()
                    if not name:
                        return  # Can't ban, name unknown
                    Bukkit.getBanList(BanList.Type.NAME).addBan(name, reason, expires, source) if self.ban else Bukkit.getBanList(BanList.Type.NAME).pardon(name)

    def __str__(self):
        return f"{'IP-' if self.ip_ban else ''}{('un' if not self.ban else '')}ban {self.players} {' on account of ' + str(self.reason) if self.reason else ''} {' for ' + str(self.expires) if self.expires else ''}"
