/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gemstone.gemfire.management.internal.security;

import com.gemstone.gemfire.internal.AvailablePort;
import com.gemstone.gemfire.management.DiskStoreMXBean;
import com.gemstone.gemfire.test.junit.categories.IntegrationTest;
import org.apache.shiro.ShiroException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Category(IntegrationTest.class)
public class DiskStoreMXBeanSecurityJUnitTest {
  private static int jmxManagerPort = AvailablePort.getRandomAvailablePort(AvailablePort.SOCKET);

  private DiskStoreMXBean bean;

  @ClassRule
  public static JsonAuthorizationCacheStartRule serverRule = new JsonAuthorizationCacheStartRule(
      jmxManagerPort, "cacheServer.json");

  @Rule
  public MBeanServerConnectionRule connectionRule = new MBeanServerConnectionRule(jmxManagerPort);

  @BeforeClass
  public static void beforeClass(){
    serverRule.getCache().createDiskStoreFactory().create("diskstore");
  }

  @Before
  public void setUp() throws Exception {
    bean = connectionRule.getProxyMBean(DiskStoreMXBean.class);
  }

  @Test
  @JMXConnectionConfiguration(user = "superuser", password = "1234567")
  public void testAllAccess() throws Exception {
    bean.flush();
    bean.forceCompaction();
    bean.forceRoll();
    bean.getCompactionThreshold();
    bean.getDiskDirectories();
    bean.getDiskReadsRate();
    bean.isAutoCompact();
    bean.isForceCompactionAllowed();
    bean.setDiskUsageCriticalPercentage(0.5f);
    bean.setDiskUsageWarningPercentage(0.5f);
  }

  @Test
  @JMXConnectionConfiguration(user = "stranger", password = "1234567")
  public void testNoAccess() throws Exception {
    assertThatThrownBy(() -> bean.flush()).isInstanceOf(ShiroException.class).hasMessageContaining("DISKSTORE:FLUSH");
    assertThatThrownBy(() -> bean.forceCompaction()).hasMessageContaining("DISKSTORE:COMPACT");
    assertThatThrownBy(() -> bean.forceRoll()).hasMessageContaining("DISKSTORE:ROLL");
    assertThatThrownBy(() -> bean.getCompactionThreshold()).hasMessageContaining("JMX:GET");
    assertThatThrownBy(() -> bean.getDiskDirectories()).hasMessageContaining("JMX:GET");
    assertThatThrownBy(() -> bean.getDiskReadsRate()).hasMessageContaining("JMX:GET");
    assertThatThrownBy(() -> bean.isAutoCompact()).hasMessageContaining("JMX:GET");
    assertThatThrownBy(() -> bean.isForceCompactionAllowed()).hasMessageContaining("JMX:GET");
    assertThatThrownBy(() -> bean.setDiskUsageCriticalPercentage(0.5f)).hasMessageContaining("DISKSTORE:ALTER");
    assertThatThrownBy(() -> bean.setDiskUsageWarningPercentage(0.5f)).hasMessageContaining("DISKSTORE:ALTER");
  }
}
