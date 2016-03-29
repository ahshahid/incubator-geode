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

import com.gemstone.gemfire.distributed.internal.DistributionConfig;
import com.gemstone.gemfire.internal.ClassLoadUtil;
import com.gemstone.gemfire.internal.i18n.LocalizedStrings;
import com.gemstone.gemfire.internal.lang.StringUtils;
import com.gemstone.gemfire.management.internal.security.ResourceOperationContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import javax.management.remote.JMXAuthenticator;
import javax.management.remote.JMXPrincipal;
import javax.security.auth.Subject;
import java.lang.reflect.Method;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static com.gemstone.gemfire.management.internal.security.ResourceConstants.ACCESS_DENIED_MESSAGE;
import static com.gemstone.gemfire.management.internal.security.ResourceConstants.WRONGE_CREDENTIALS_MESSAGE;

public class CustomAuthRealm extends AuthorizingRealm implements JMXAuthenticator {
  public static final String REALM_NAME = "CUSTOMAUTHREALM";
  public static final String USER_NAME = "security-username";
  public static final String PASSWORD = "security-password";

  private static final Logger logger = LogManager.getLogger(CustomAuthRealm.class);
  private String authzFactoryName;
  private String postAuthzFactoryName;
  private String authenticatorFactoryName;
  private Properties securityProps = null;
  private ConcurrentMap<Principal, AccessControl> cachedAuthZCallback;
  private ConcurrentMap<Principal, AccessControl> cachedPostAuthZCallback;

  public CustomAuthRealm(Properties securityProps) {
    this.securityProps = securityProps;
    this.authzFactoryName = securityProps.getProperty(DistributionConfig.SECURITY_CLIENT_ACCESSOR_NAME);
    this.postAuthzFactoryName = securityProps.getProperty(DistributionConfig.SECURITY_CLIENT_ACCESSOR_PP_NAME);
    this.authenticatorFactoryName = securityProps.getProperty(DistributionConfig.SECURITY_CLIENT_AUTHENTICATOR_NAME);

    this.cachedAuthZCallback = new ConcurrentHashMap<>();
    this.cachedPostAuthZCallback = new ConcurrentHashMap<>();
    logger.info("Started Management interceptor on JMX connector");
  }


  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    UsernamePasswordToken authToken = (UsernamePasswordToken) token;
    String username = authToken.getUsername();
    String password = new String(authToken.getPassword());

    Properties credentialProps = new Properties();
    credentialProps.put(USER_NAME, username);
    credentialProps.put(PASSWORD, password);

    Principal principal  = getAuthenticator(securityProps).authenticate(credentialProps);

    return new SimpleAuthenticationInfo(principal, authToken.getPassword(), REALM_NAME);
  }


  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    // we intercepted the call to this method by overriding the isPermitted call
    return null;
  }

  @Override
  public boolean isPermitted(PrincipalCollection principals, Permission permission) {
    ResourceOperationContext context = (ResourceOperationContext) permission;
    Principal principal = (Principal)principals.getPrimaryPrincipal();

    AccessControl accessControl = getAccessControl(principal, false);
    return accessControl.authorizeOperation(null, context);
  }


  @Override
  public Subject authenticate(Object credentials) {
    String username = null, password = null;
    if (credentials instanceof String[]) {
      final String[] aCredentials = (String[]) credentials;
      username = aCredentials[0];
      password = aCredentials[1];
    } else if (credentials instanceof Properties) {
      username = ((Properties) credentials).getProperty(USER_NAME);
      password = ((Properties) credentials).getProperty(PASSWORD);
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

  public AccessControl getAccessControl(Principal principal, boolean isPost) {
    if (!isPost) {
      if (cachedAuthZCallback.containsKey(principal)) {
        return cachedAuthZCallback.get(principal);
      } else if (!StringUtils.isBlank(authzFactoryName)) {
        try {
          Method authzMethod = ClassLoadUtil.methodFromName(authzFactoryName);
          AccessControl authzCallback = (AccessControl) authzMethod.invoke(null, (Object[]) null);
          authzCallback.init(principal, null);
          cachedAuthZCallback.put(principal, authzCallback);
          return authzCallback;
        } catch (Exception ex) {
          throw new AuthenticationFailedException(
              LocalizedStrings.HandShake_FAILED_TO_ACQUIRE_AUTHENTICATOR_OBJECT.toLocalizedString(), ex);
        }
      }
    } else {
      if (cachedPostAuthZCallback.containsKey(principal)) {
        return cachedPostAuthZCallback.get(principal);
      } else if (!StringUtils.isBlank(postAuthzFactoryName)) {
        try {
          Method authzMethod = ClassLoadUtil.methodFromName(postAuthzFactoryName);
          AccessControl postAuthzCallback = (AccessControl) authzMethod.invoke(null, (Object[]) null);
          postAuthzCallback.init(principal, null);
          cachedPostAuthZCallback.put(principal, postAuthzCallback);
          return postAuthzCallback;
        } catch (Exception ex) {
          throw new AuthenticationFailedException(
              LocalizedStrings.HandShake_FAILED_TO_ACQUIRE_AUTHENTICATOR_OBJECT.toLocalizedString(), ex);
        }
      }
    }
    return null;
  }

  private Authenticator getAuthenticator(Properties gfSecurityProperties) throws AuthenticationFailedException {
    Authenticator auth;
    try {
      Method instanceGetter = ClassLoadUtil.methodFromName(this.authenticatorFactoryName);
      auth = (Authenticator) instanceGetter.invoke(null, (Object[]) null);
    } catch (Exception ex) {
      throw new AuthenticationFailedException(
          LocalizedStrings.HandShake_FAILED_TO_ACQUIRE_AUTHENTICATOR_OBJECT.toLocalizedString(), ex);
    }
    if (auth == null) {
      throw new AuthenticationFailedException(
          LocalizedStrings.HandShake_AUTHENTICATOR_INSTANCE_COULD_NOT_BE_OBTAINED.toLocalizedString());
    }
    auth.init(gfSecurityProperties);
    return auth;
  }

  public void postAuthorize(ResourceOperationContext context) {
    if (StringUtils.isBlank(postAuthzFactoryName)){
      return ;
    }

    AccessControlContext acc = AccessController.getContext();
    Subject subject = Subject.getSubject(acc);
    Set<JMXPrincipal> principals = subject.getPrincipals(JMXPrincipal.class);
    if (principals == null || principals.isEmpty()) {
      throw new SecurityException(ACCESS_DENIED_MESSAGE);
    }
    Principal principal = principals.iterator().next();
    AccessControl accessControl = getAccessControl(principal, true);
    if (!accessControl.authorizeOperation(null, context)) {
      throw new SecurityException(ACCESS_DENIED_MESSAGE);
    }
  }

}
