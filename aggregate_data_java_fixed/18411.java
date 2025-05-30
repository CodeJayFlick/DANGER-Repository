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

package org.apache.iotdb.tsfile.read.query.timegenerator;

import org.apache.iotdb.tsfile.exception.write.WriteProcessException;
import org.apache.iotdb.tsfile.file.metadata.enums.TSDataType;
import org.apache.iotdb.tsfile.file.metadata.enums.TSEncoding;
import org.apache.iotdb.tsfile.read.ReadOnlyTsFile;
import org.apache.iotdb.tsfile.read.TsFileSequenceReader;
import org.apache.iotdb.tsfile.read.common.Path;
import org.apache.iotdb.tsfile.read.expression.IExpression;
import org.apache.iotdb.tsfile.read.expression.QueryExpression;
import org.apache.iotdb.tsfile.read.expression.impl.BinaryExpression;
import org.apache.iotdb.tsfile.read.expression.impl.GlobalTimeExpression;
import org.apache.iotdb.tsfile.read.expression.impl.SingleSeriesExpression;
import org.apache.iotdb.tsfile.read.filter.TimeFilter;
import org.apache.iotdb.tsfile.read.filter.ValueFilter;
import org.apache.iotdb.tsfile.read.filter.basic.Filter;
import org.apache.iotdb.tsfile.read.filter.factory.FilterFactory;
import org.apache.iotdb.tsfile.read.query.dataset.QueryDataSet;
import org.apache.iotdb.tsfile.utils.TsFileGeneratorForTest;
import org.apache.iotdb.tsfile.write.TsFileWriter;
import org.apache.iotdb.tsfile.write.record.TSRecord;
import org.apache.iotdb.tsfile.write.record.datapoint.DataPoint;
import org.apache.iotdb.tsfile.write.record.datapoint.FloatDataPoint;
import org.apache.iotdb.tsfile.write.record.datapoint.IntDataPoint;
import org.apache.iotdb.tsfile.write.schema.Schema;
import org.apache.iotdb.tsfile.write.schema.UnaryMeasurementSchema;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

public class TimeGeneratorReadWriteTest {

  private final String TEMPLATE_NAME = "template";
  private final String tsfilePath = TsFileGeneratorForTest.getTestTsFilePath("root.sg1", 0, 0, 1);

  @Before
  public void before() throws IOException, WriteProcessException {
    writeTsFile(tsfilePath);
  }

  @After
  public void after() {
    File file = new File(tsfilePath);
    if (file.exists()) {
      file.delete();
    }
  }

  @Test
  public void testFilterAnd() throws IOException {
    Filter timeFilter = FilterFactory.and(TimeFilter.gtEq(1L), TimeFilter.ltEq(8L));
    IExpression timeExpression = new GlobalTimeExpression(timeFilter);

    IExpression valueExpression =
        BinaryExpression.and(
            new SingleSeriesExpression(new Path("d1", "s1"), ValueFilter.gt(1.0f)),
            new SingleSeriesExpression(new Path("d1", "s2"), ValueFilter.lt(22)));

    IExpression finalExpression = BinaryExpression.and(valueExpression, timeExpression);

    QueryExpression queryExpression =
        QueryExpression.create()
            .addSelectedPath(new Path("d1", "s1"))
            .addSelectedPath(new Path("d1", "s2"))
            .setExpression(finalExpression);

    try (TsFileSequenceReader fileReader = new TsFileSequenceReader(tsfilePath)) {
      ReadOnlyTsFile readOnlyTsFile = new ReadOnlyTsFile(fileReader);
      QueryDataSet dataSet = readOnlyTsFile.query(queryExpression);
      int i = 0;
      String[] expected = new String[] {"2\t1.2\t20", "3\t1.2\t20", "4\t1.2\t20", "5\t1.2\t20"};
      while (dataSet.hasNext()) {
        Assert.assertEquals(expected[i], dataSet.next().toString());
        i++;
      }
      Assert.assertEquals(4, i);
    }
  }

  /** s1 -> 1, 2, 3, 4, 5 s2 -> 2, 3, 4, 5, 6 */
  private void writeTsFile(String tsfilePath) throws IOException, WriteProcessException {
    File f = new File(tsfilePath);
    if (f.exists()) {
      f.delete();
    }
    if (!f.getParentFile().exists()) {
      Assert.assertTrue(f.getParentFile().mkdirs());
    }

    Schema schema = new Schema();
    schema.extendTemplate(
        TEMPLATE_NAME, new UnaryMeasurementSchema("s1", TSDataType.FLOAT, TSEncoding.RLE));
    schema.extendTemplate(
        TEMPLATE_NAME, new UnaryMeasurementSchema("s2", TSDataType.INT32, TSEncoding.TS_2DIFF));

    TsFileWriter tsFileWriter = new TsFileWriter(new File(tsfilePath), schema);

    // s1 -> 1, 2, 3
    TSRecord tsRecord = new TSRecord(1, "d1");
    DataPoint dPoint1 = new FloatDataPoint("s1", 1.2f);
    tsRecord.addTuple(dPoint1);
    tsFileWriter.write(tsRecord);

    tsRecord = new TSRecord(2, "d1");
    dPoint1 = new FloatDataPoint("s1", 1.2f);
    tsRecord.addTuple(dPoint1);
    tsFileWriter.write(tsRecord);

    tsRecord = new TSRecord(3, "d1");
    dPoint1 = new FloatDataPoint("s1", 1.2f);
    tsRecord.addTuple(dPoint1);
    tsFileWriter.write(tsRecord);

    tsFileWriter.flushAllChunkGroups();

    // s2 -> 2, 3, 4
    tsRecord = new TSRecord(2, "d1");
    DataPoint dPoint2 = new IntDataPoint("s2", 20);
    tsRecord.addTuple(dPoint2);
    tsFileWriter.write(tsRecord);

    tsRecord = new TSRecord(3, "d1");
    dPoint2 = new IntDataPoint("s2", 20);
    tsRecord.addTuple(dPoint2);
    tsFileWriter.write(tsRecord);

    tsRecord = new TSRecord(4, "d1");
    dPoint2 = new IntDataPoint("s2", 20);
    tsRecord.addTuple(dPoint2);
    tsFileWriter.write(tsRecord);

    tsFileWriter.flushAllChunkGroups();

    // s1 -> 4, 5
    tsRecord = new TSRecord(4, "d1");
    dPoint1 = new FloatDataPoint("s1", 1.2f);
    tsRecord.addTuple(dPoint1);
    tsFileWriter.write(tsRecord);

    tsRecord = new TSRecord(5, "d1");
    dPoint1 = new FloatDataPoint("s1", 1.2f);
    tsRecord.addTuple(dPoint1);
    tsFileWriter.write(tsRecord);

    tsFileWriter.flushAllChunkGroups();

    // s2 -> 5, 6
    tsRecord = new TSRecord(5, "d1");
    dPoint2 = new IntDataPoint("s2", 20);
    tsRecord.addTuple(dPoint2);
    tsFileWriter.write(tsRecord);

    tsRecord = new TSRecord(6, "d1");
    dPoint2 = new IntDataPoint("s2", 20);
    tsRecord.addTuple(dPoint2);
    tsFileWriter.write(tsRecord);

    // close TsFile
    tsFileWriter.close();
  }
}
