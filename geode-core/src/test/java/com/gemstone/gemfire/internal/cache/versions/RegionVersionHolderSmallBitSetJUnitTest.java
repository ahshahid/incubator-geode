/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gemstone.gemfire.internal.cache.versions;

import org.junit.experimental.categories.Category;

import com.gemstone.gemfire.test.junit.categories.UnitTest;

/**
 * A test of the region version holder, but using a smaller bit
 * set so that we test the merging of exceptions functionality.
 */
@Category(UnitTest.class)
public class RegionVersionHolderSmallBitSetJUnitTest extends RegionVersionHolderJUnitTest {
  
  
  @Override
  protected void setUp() throws Exception {
    super.setUp();
    originalBitSetWidth = RegionVersionHolder.BIT_SET_WIDTH;
    RegionVersionHolder.BIT_SET_WIDTH = 4;
  }
  
  protected void tearDown() throws Exception {
    super.tearDown();
    RegionVersionHolder.BIT_SET_WIDTH = originalBitSetWidth;
  }
  
  
  

}
