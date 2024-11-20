import unittest

class HistoryListTest(unittest.TestCase):

    def setUp(self):
        self.selected_items = []
        self.callback = lambda s: self.selected_items.append(s)
        self.history_list = FixedSizeStack(max_size=10, callback=self.callback)

    @unittest.skip("Not implemented")
    def testBasicNavigation(self):
        add_history('A')
        add_history('B')
        add_history('C')
        add_history('D')

        assert_history(['A', 'B', 'C', 'D'])

        go_back()
        assert_notified('C')
        go_back()
        assert_notified('B')
        go_back()
        assert_notified('A')
        assert_history(['A', 'B', 'C', 'D'])

        assert_cannot_go_back()

        go_forward()
        assert_notified('B')
        go_forward()
        assert_notified('C')
        go_forward()
        assert_notified('D')

        assert_cannot_go_forward()

    @unittest.skip("Not implemented")
    def testAddingNewItem_AtBeginningOfStack(self):
        add_history('A')
        add_history('B')
        add_history('C')
        add_history('D')

        go_back()
        assert_notified('C')
        go_back()
        assert_notified('B')
        go_back()
        assert_notified('A')

        assert_cannot_go_back()

        self.history_list.set_allow_nulls(True)
        add_history('E')

        assert_can_go_back()
        assert_cannot_go_forward()

    @unittest.skip("Not implemented")
    def testAddingNewItem_AtMiddleOfStack(self):
        add_history('A')
        add_history('B')
        add_history('C')
        add_history('D')

        go_back()
        assert_notified('C')

        self.history_list.set_allow_nulls(True)
        add_history('E')

        assert_can_go_back()
        assert_cannot_go_forward()

    @unittest.skip("Not implemented")
    def testAddingDuringCallbackDoesNothing(self):
        history_list = FixedSizeStack(max_size=10, callback=lambda s: [self.selected_items.append(s), self.add_history(s)])
        add_history('A')
        add_history('B')
        add_history('C')
        add_history('D')

        assert_history(['A', 'B', 'C', 'D'])

    @unittest.skip("Not implemented")
    def testNavigationMixedWithHistoryAddition(self):
        add_history('A')
        add_history('B')
        assert_history(['A', 'B'])
        go_back()
        assert_history(['A', 'B'])
        self.history_list.set_allow_nulls(True)
        add_history('C')

        # Since we don't allow duplicates, A gets moved
        assert_history(['C', 'A'])

    @unittest.skip("Not implemented")
    def testNull_NullNotAllowed(self):
        add_history('A')
        with self.assertRaises(IndexError):  # This is a placeholder for the exception that should be raised.
            add_history(None)

    @unittest.skip("Not implemented")
    def testNull_NullAllowed(self):
        self.history_list.set_allow_nulls(True)
        add_history('A')
        add_history(None)
        assert_history(['A', None])

    @unittest.skip("Not implemented")
    def testNull_WhenEmpty(self):
        self.history_list.set_allow_nulls(True)
        with self.assertRaises(IndexError):  # This is a placeholder for the exception that should be raised.
            add_history(None)

    @unittest.skip("Not implemented")
    def testNull_GoBack(self):
        self.history_list.set_allow_nulls(True)
        add_history('A')
        add_history(1)  # Replace this with None
        assert_history(['A', 'B'])
        go_back()
        assert_notified(None)

    @unittest.skip("Not implemented")
    def testNull_GoBack_GoForward(self):
        self.history_list.set_allow_nulls(True)
        add_history('A')
        add_history(1)  # Replace this with None
        assert_history(['A', 'B'])
        go_back()
        assert_notified(None)

    @unittest.skip("Not implemented")
    def testNull_GetCurrentHistoryItem(self):
        self.history_list.set_allow_nulls(True)
        add_history('A')
        add_history(1)  # Replace this with None
        assert_current_item(None)

    @unittest.skip("Not implemented")
    def testNull_GetPreviousAndNextItems(self):
        self.history_list.set_allow_nulls(True)
        add_history('A')
        add_history(1)  # Replace this with None
        assert_previous_items(['B', 'A'])
        assert_next_items()

    @unittest.skip("Not implemented")
    def testRepeatedAdds_DoesntAddSameItemTwice(self):
        add_history('A')
        add_history('B')
        assert_history(['A', 'B'])

        add_history('B')

        # Since we don't allow duplicates, B gets moved
        assert_history(['A', 'B'])

    @unittest.skip("Not implemented")
    def testRepeatedAdds_DontAllowDuplicates_IndexGetsChanged(self):
        self.history_list.set_allow_duplicates(False)
        add_history('A')
        add_history('B')
        add_history('C')

        # Since we don't allow duplicates, A gets moved
        assert_history(['B', 'C'])

    @unittest.skip("Not implemented")
    def testRepeatedAdds_AllowDuplicates_ItemGetsAdded(self):
        self.history_list.set_allow_duplicates(True)
        add_history('A')
        add_history('B')
        add_history('C')

        # Since we do allow duplicates, A gets added
        assert_history(['A', 'B', 'C'])

    @unittest.skip("Not implemented")
    def testGetPreviousAndNextHistoryItems(self):
        add_history('A')
        add_history('B')
        add_history('C')
        add_history('D')

        # Since we don't allow duplicates, A gets moved
        assert_previous_items(['B', 'A'])
        assert_next_items()

    @unittest.skip("Not implemented")
    def testBackToItem(self):
        self.history_list.set_allow_duplicates(True)
        add_history('A')
        add_history('B')

        # Since we do allow duplicates, B gets added
        history_list.go_back_to('A')
        assert_current_item('A')

    @unittest.skip("Not implemented")
    def testForwardToItem(self):
        self.history_list.set_allow_duplicates(True)
        add_history('A')
        add_history('B')
        go_back()
        go_back()

        # Since we do allow duplicates, A gets added
        history_list.go_forward_to('C')

        assert_current_item('C')

    def testBasicNavigation(self):
        pass

    def testAddingNewItem_AtBeginningOfStack(self):
        pass

    def testAddingNewItem_AtMiddleOfStack(self):
        pass

    def testAddingDuringCallbackDoesNothing(self):
        pass

    def testNavigationMixedWithHistoryAddition(self):
        pass

    def testNull_NullNotAllowed(self):
        pass

    def testNull_NullAllowed(self):
        pass

    def testNull_WhenEmpty(self):
        pass

    def testNull_GoBack(self):
        pass

    def testNull_GoBack_GoForward(self):
        pass

    def testNull_GetCurrentHistoryItem(self):
        pass

    def testNull_GetPreviousAndNextItems(self):
        pass

    def testRepeatedAdds_DoesntAddSameItemTwice(self):
        pass

    def testRepeatedAdds_DontAllowDuplicates_IndexGetsChanged(self):
        pass

    def testRepeatedAdds_AllowDuplicates_ItemGetsAdded(self):
        pass

    def testGetPreviousAndNextHistoryItems(self):
        pass

    def testBackToItem(self):
        pass

    def testForwardToItem(self):
        pass

if __name__ == '__main__':
    unittest.main()
