class HealReason:
    def __init__(self):
        self.name = "Heal Reason"
        self.description = ("The heal reason of a heal event."
                            " Please click on the link for more information.")
        self.examples = ["on heal:",
                         "\tif heal reason  = satiated:",
                         "\t\tsend \"You ate enough food and gained health back!\" to player"]
        self.since = "2.5"

    def register_expression(self):
        Skript.register_expression(HealReason, RegainReason, ExpressionType.SIMPLE,
                                  "(regen|health regain|heal) (reason|cause)")

    def init(self, exprs, matched_pattern, is_delayed, parse_result):
        if not get_parser().is_current_event(EntityRegainHealthEvent):
            Skript.error("Heal reason can only be used in an on heal event", ErrorQuality.SEMANTIC_ERROR)
            return False
        return True

    def get(self, e):
        return [(EntityRegainHealthEvent(e)).get_regain_reason()]

    @property
    def is_single(self):
        return True

    @property
    def return_type(self):
        return RegainReason.__class__

    def __str__(self, e=None, debug=False):
        if not e:
            return "heal reason"
        else:
            return str(e)

# Usage example:

HealReason().register_expression()
