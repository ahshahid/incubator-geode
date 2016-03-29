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
package com.gemstone.gemfire.security;

import com.gemstone.gemfire.management.internal.security.ResourceConstants;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;

import javax.management.remote.JMXAuthenticator;
import javax.security.auth.Subject;
import java.util.Properties;

import static com.gemstone.gemfire.management.internal.security.ResourceConstants.WRONGE_CREDENTIALS_MESSAGE;

/**
 * this will make JMX authentication to use Shiro for Authentication
 */

public class JMXShiroAuthenticator implements JMXAuthenticator {

  @Override
  public Subject authenticate(Object credentials) {
    String username = null, password = null;
    if (credentials instanceof String[]) {
      final String[] aCredentials = (String[]) credentials;
      username = aCredentials[0];
      password = aCredentials[1];
    } else if (credentials instanceof Properties) {
      username = ((Properties) credentials).getProperty(ResourceConstants.USER_NAME);
      password = ((Properties) credentials).getProperty(ResourceConstants.PASSWORD);
    } else {
      throw new SecurityException(WRONGE_CREDENTIALS_MESSAGE);
    }

    AuthenticationToken token =
        new UsernamePasswordToken(username, password);
    org.apache.shiro.subject.Subject currentUser = SecurityUtils.getSubject();
    currentUser.login(token);

    // we are not using JMX mechanism to do authentication, therefore, this return value does not matter
    return null;
  }

  public void logout(){
    org.apache.shiro.subject.Subject currentUser = SecurityUtils.getSubject();
    currentUser.logout();
  }
}
