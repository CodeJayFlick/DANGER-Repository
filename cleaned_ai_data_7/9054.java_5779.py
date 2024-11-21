import logging

class SetMarkupItemConsideredTask:
    def __init__(self, session: 'VTSessionDB', markup_items: list['VTMarkupItem'], status: 'VTMarkupItemConsideredStatus'):
        self.markup_items = markup_items
        self.session = session
        self.status = status

    def run(self):
        commit = True

        try:
            do_work()
        except CancelledException as e:
            commit = False
        except Exception as e:
            logging.error("Unable to Apply Markup Item(s)", exc_info=e)
            commit = False

        finally:
            self.session.end_transaction(match_set_transaction_id, commit)

    def do_work(self):
        for markup_item in self.markup_items:
            if self.monitor.check_cancelled():
                break
            markup_item.set_considered(self.status)
