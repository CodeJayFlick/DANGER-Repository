Here is your Java code translated into equivalent Python:

```Python
import unittest
from ghidra.app.services import DuplicateNameException
class ProgramTreeMergeManager2Test(unittest.TestCase):
    def test_nameConflictOpt1(self):

        mtf = self.merger("notepad", new ProgramModifierListener()  {
            @Override
            public void modifyLatest(ProgramDB program) {

                boolean commit = false;
                Listing listing = program.getListing();
                int transactionID = program.startTransaction("test");
                try {
                    // for case 1: "other" name changed, "private" name changed
                    ProgramModule root = listing.getRootModule("Main Tree");
                    root.createFragment("frag_one");
                    root.createModule("my module");

                    commit = true;
                } catch (DuplicateNameException e) {
                    self.fail("Got Duplicate name exception!");
                } finally {
                    program.endTransaction(transactionID, commit);
                }

            }
        });

        merge();
        selectButtonAndApply("Use name 'Some Other Tree'")

    def test_nameConflictOpt2(self):
        mtf = self.merger("notepad", new ProgramModifierListener()  {
            @Override
            public void modifyLatest(ProgramDB program) {

                boolean commit = false;
                Listing listing = program.getListing();
                int transactionID = program.startTransaction("test");
                try {
                    // for case 1: "other" name changed, "private" name changed

                    ProgramModule root = listing.getRootModule("Main Tree");

                    root.createFragment("frag_one");
                    root.createModule("my module");

                    commit = true;
                } catch (DuplicateNameException e) {
                    self.fail("Got Duplicate name exception!");
                } finally {
                    program.endTransaction(transactionID, commit);
                }

            }
        });

        merge();
        selectButtonAndApply(1)

    def test_nameConflictOpt3(self):
        mtf = self.merger("notepad", new ProgramModifierListener()  {
            @Override
            public void modifyLatest(ProgramDB program) {

                boolean commit = false;
                Listing listing = program.getListing();

                int transactionID = program.startTransaction("test");
                try {
                    // for case: "other" name changed, "private" name changed

                    ProgramModule root = listing.getRootModule("Main Tree");

                    root.createFragment("frag_one");
                    root.createModule("my module");

                    commit = true;
                } catch (DuplicateNameException e) {
                        self.fail("Got Duplicate name exception!
                } finally {
                    program.endTransaction(transactionID, commit);
                }

            @Override
            public void modifyLatest(ProgramDB program) {

                boolean commit = false;
                Listing listing = program.getListing();

                int transactionID = 1;

                try {
                    // for case: "other" name changed

                } catch DuplicateNameException e)
                } finally {
                    program.endTransaction(transactionID,commit);
                }

            @Override
            public void modifyLatest(ProgramDB program) {

                boolean commit = false;
                }
            public void (false;

                }
            public void (false;                }
            public void (false;
                } catch DuplicateNameException e

                } finally {
                    program.endTransaction(transactionID,commit;
                }

            @Override
            public void modifyLatest(ProgramDB program.getListing();

                } catch DuplicateNameException e

                } catch duplicate name exception!
                } catch DuplicateNameException e
                }
            public void (false;

                } catch DuplicateNameException e
                } catch duplicate name exception!

                } catch DuplicateNameException e
                } catch duplicate name exception!
                } catch DuplicateNameException e
                } catch duplicate name exception!