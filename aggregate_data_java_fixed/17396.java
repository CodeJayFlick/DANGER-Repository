/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.iotdb.db.query.control;

import org.apache.iotdb.db.engine.StorageEngine;
import org.apache.iotdb.db.engine.querycontext.QueryDataSource;
import org.apache.iotdb.db.exception.StorageEngineException;
import org.apache.iotdb.db.exception.query.QueryProcessException;
import org.apache.iotdb.db.metadata.PartialPath;
import org.apache.iotdb.db.query.context.QueryContext;
import org.apache.iotdb.db.query.control.tracing.TracingManager;
import org.apache.iotdb.db.query.externalsort.serialize.IExternalSortFileDeserializer;
import org.apache.iotdb.db.query.udf.service.TemporaryQueryDataFileService;
import org.apache.iotdb.tsfile.read.expression.impl.SingleSeriesExpression;
import org.apache.iotdb.tsfile.read.filter.basic.Filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * QueryResourceManager manages resource (file streams) used by each query job, and assign Ids to
 * the jobs. During the life cycle of a query, the following methods must be called in strict order:
 * 1. assignQueryId - get an Id for the new query. 2. getQueryDataSource - open files for the job or
 * reuse existing readers. 3. endQueryForGivenJob - release the resource used by this job.
 */
public class QueryResourceManager {

  private final AtomicLong queryIdAtom = new AtomicLong();
  private final QueryFileManager filePathsManager;

  /**
   * Record temporary files used for external sorting.
   *
   * <p>Key: query job id. Value: temporary file list used for external sorting.
   */
  private final Map<Long, List<IExternalSortFileDeserializer>> externalSortFileMap;

  private QueryResourceManager() {
    filePathsManager = new QueryFileManager();
    externalSortFileMap = new ConcurrentHashMap<>();
  }

  public static QueryResourceManager getInstance() {
    return QueryTokenManagerHelper.INSTANCE;
  }

  /** Register a new query. When a query request is created firstly, this method must be invoked. */
  public long assignQueryId(boolean isDataQuery) {
    long queryId = queryIdAtom.incrementAndGet();
    if (isDataQuery) {
      filePathsManager.addQueryId(queryId);
    }
    return queryId;
  }

  /**
   * register temporary file generated by external sort for resource release.
   *
   * @param queryId query job id
   * @param deserializer deserializer of temporary file in external sort.
   */
  public void registerTempExternalSortFile(
      long queryId, IExternalSortFileDeserializer deserializer) {
    externalSortFileMap.computeIfAbsent(queryId, x -> new ArrayList<>()).add(deserializer);
  }

  public QueryDataSource getQueryDataSource(
      PartialPath selectedPath, QueryContext context, Filter filter)
      throws StorageEngineException, QueryProcessException {

    SingleSeriesExpression singleSeriesExpression =
        new SingleSeriesExpression(selectedPath, filter);
    QueryDataSource queryDataSource =
        StorageEngine.getInstance().query(singleSeriesExpression, context, filePathsManager);

    // for tracing: calculate the distinct number of seq and unseq tsfiles
    if (context.isEnableTracing()) {
      TracingManager.getInstance()
          .addTsFileSet(
              context.getQueryId(),
              queryDataSource.getSeqResources(),
              queryDataSource.getUnseqResources());
    }
    return queryDataSource;
  }

  /**
   * Whenever the jdbc request is closed normally or abnormally, this method must be invoked. All
   * query tokens created by this jdbc request must be cleared.
   */
  @SuppressWarnings("squid:S3776") // Suppress high Cognitive Complexity warning
  public void endQuery(long queryId) throws StorageEngineException {
    // close file stream of external sort files, and delete
    if (externalSortFileMap.get(queryId) != null) {
      for (IExternalSortFileDeserializer deserializer : externalSortFileMap.get(queryId)) {
        try {
          deserializer.close();
        } catch (IOException e) {
          throw new StorageEngineException(e);
        }
      }
      externalSortFileMap.remove(queryId);
    }

    // remove usage of opened file paths of current thread
    filePathsManager.removeUsedFilesForQuery(queryId);

    // close and delete UDF temp files
    TemporaryQueryDataFileService.getInstance().deregister(queryId);

    // remove query info in QueryTimeManager
    QueryTimeManager.getInstance().unRegisterQuery(queryId, true);
  }

  private static class QueryTokenManagerHelper {

    private static final QueryResourceManager INSTANCE = new QueryResourceManager();

    private QueryTokenManagerHelper() {}
  }
}
