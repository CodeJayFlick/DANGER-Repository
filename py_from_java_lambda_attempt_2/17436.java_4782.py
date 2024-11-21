Here is the translation of the Java interface `IQueryRouter` to a Python class:

```python
class IQueryRouter:
    def __init__(self):
        pass

    def rawData_query(self, query_plan: 'RawDataQueryPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("raw_data_query not implemented")

    def aggregate(self, aggregation_plan: 'AggregationPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("aggregate not implemented")

    def group_by(self, group_by_time_plan: 'GroupByTimePlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("group_by not implemented")

    def fill(self, fill_query_plan: 'FillQueryPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("fill not implemented")

    def group_by_fill(self, group_by_fill_plan: 'GroupByTimeFillPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("group_by_fill not implemented")

    def last_query(self, last_query_plan: 'LastQueryPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("last_query not implemented")

    def udtf_query(self, udtf_plan: 'UDTFPlan', context: 'QueryContext') -> 'QueryDataSet':
        # TO DO: implement this method
        raise NotImplementedError("udtf_query not implemented")
```

Note that I've used the `NotImplementedError` exception to indicate that these methods are not yet implemented. You will need to fill in the implementation details for each method based on your specific requirements.

Also, note that Python does not have a direct equivalent of Java's interface concept. Instead, we use abstract base classes (ABCs) or interfaces defined using the `abc` module from the standard library. In this case, I've used an abstract class to define the methods and their signatures.