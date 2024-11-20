class ClearMatchTagTask:
    def __init__(self, session: 'VTSession', matches):
        self.session = session
        self.matches = matches

    def run(self):
        commit = True
        match_set_transaction_id = self.session.start_transaction("Clear Match Tag")
        try:
            self.do_work()
        except CancelledException as e:
            commit = False
        finally:
            self.session.end_transaction(match_set_transaction_id, commit)

    def do_work(self):
        for i, match in enumerate(self.matches):
            if match.get_tag() == VTMatchTag.UNTAGGED:
                continue

            match.set_tag(VTMatchTag.UNTAGGED)
