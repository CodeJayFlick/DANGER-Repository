Here is the translation of the given Java code into Python:

```Python
class EffSendTitle:
    TIME_SUPPORTED = hasattr(bukkit.Player, 'send_title')

    def __init__(self):
        self.title = None
        self.subtitle = None
        self.recipients = None
        self.fade_in = None
        self.stay = None
        self.fade_out = None

    @staticmethod
    def register_effect():
        if EffSendTitle.TIME_SUPPORTED:
            Skript.register_event('send title %string% [with subtitle %-string%] [to %players%] [for %-timespan%] [with fade[(-| )in %-timespan%] [(and|with) fade[(-| )out %-timespan%]', 'send subtitle %string% [to %players%] [for %-timespan%] [with fade[(-| )in %-timespan%] [(and|with) fade[(-| )out %-timespan%]')
        else:
            Skript.register_event('send title %string% [with subtitle %-string%] [to %players%', 'send subtitle %string% [to %players%')

    def init(self, exprs):
        self.title = exprs[0]
        self.subtitle = exprs[-1 - len(exprs)]
        self.recipients = exprs[-2 - len(exprs)]

        if EffSendTitle.TIME_SUPPORTED:
            self.fade_in = exprs[-3 - len(exprs)]
            self.stay = exprs[-4 - len(exprs)]
            self.fade_out = exprs[-5 - len(exprs)]

    def execute(self, e):
        title = self.title.get_single(e) if self.title else ''
        sub = self.subtitle.get_single(e) if self.subtitle else None

        if EffSendTitle.TIME_SUPPORTED:
            in_time = int(self.fade_in.get_single(e).get_ticks_i()) if self.fade_in else -1
            stay_time = int(self.stay.get_single(e).get_ticks_i()) if self.stay else -1
            out_time = int(self.fade_out.get_single(e).get_ticks_i()) if self.fade_out else -1

            for p in self.recipients.get_array(e):
                p.send_title(title, sub, in_time, stay_time, out_time)
        else:
            for p in self.recipients.get_array(e):
                p.send_title(title, sub)

    def __str__(self, e, debug=False):
        title = str(self.title) if self.title else ''
        sub = str(self.subtitle) if self.subtitle else ''
        in_time = str(self.fade_in) if self.fade_in else ''
        stay_time = str(self.stay) if self.stay else ''
        out_time = str(self.fade_out) if self.fade_out else ''

        return f'send title {title}{" with subtitle " + sub if sub else ""}{f" to {self.recipients}" if debug else ""}' \
               f'{" for {stay_time} with fade in {in_time} and fade out {out_time}" if EffSendTitle.TIME_SUPPORTED else ""}
```

Please note that this is a direct translation of the given Java code into Python, without considering any potential issues or improvements.