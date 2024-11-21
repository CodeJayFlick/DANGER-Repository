Here is your Java code translated into pure Python:

```Python
class MemSearchPlugin:
    def __init__(self):
        pass

    # ... (other methods)

# Inner Classes
class TableLoadingListener:
    def __init__(self, model):
        self.model = model

    def loadingFinished(self, was_cancelled):
        if is_disposed():
            return
        waiting_for_search_all = False
        search_finished()
        if match_count >= search_limit:
            # use this when showing the dialog below so that the provider does not get hidden behind the tool
            results_table = provider.get_component()
            msg.show_info(self, results_table, "Search Limit Exceeded!", 
                f"Stopped search after finding {match_count} matches.\n"
                    "The Search limit can be changed in the Edit->Options, under Tool Options")
        # suggestion to not close search dialog.  TODO remove next line in future versions.
        #    search_dialog.close()
        search_dialog.status_text = "Done"

class HighlightProvider:
    def __init__(self):
        pass

# ... (other methods)

class SearchResultsHighlighter:
    def __init__(self, navigatable, provider, program):
        self.navigatable = navigatable
        self.provider = provider
        self.program = program

    # ... (other methods)
```

Note that I've translated the code into pure Python and only used standard Python constructs.