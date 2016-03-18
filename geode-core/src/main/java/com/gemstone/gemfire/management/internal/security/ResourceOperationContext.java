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
package com.gemstone.gemfire.management.internal.security;

import com.gemstone.gemfire.cache.operations.OperationContext;
import org.apache.shiro.authz.Permission;

/**
 * This is base class for OperationContext for resource (JMX and CLI) operations
 */
public class ResourceOperationContext extends OperationContext implements Permission{

  private boolean isPostOperation = false;
  private Object opResult = null;
  private Resource resource = null;
  private OperationCode operation = null;

  public ResourceOperationContext() {
  }

  public ResourceOperationContext(Resource resource, OperationCode operation) {
    this.resource = resource;
    this.operation = operation;
  }

  public ResourceOperationContext(String resource, String operation) {
    if (resource != null) this.resource = Resource.valueOf(resource);
    if (operation != null) this.operation = OperationCode.valueOf(operation);
  }

  public void setResourceOperation(ResourceOperation op) {
    if (op != null) {
      resource = op.resource();
      operation = op.operation();
    }
  }

  @Override
  public boolean isClientUpdate() {
    return false;
  }

  @Override
  public OperationCode getOperationCode() {
    return operation;
  }

  @Override
  public Resource getResource() {
    return resource;
  }

  @Override
  public boolean isPostOperation() {
    return isPostOperation;
  }

  public void setPostOperationResult(Object result) {
    this.isPostOperation = true;
    this.opResult = result;
  }

  public Object getOperationResult() {
    return this.opResult;
  }

  public String toString(){
    return getResource() + ":"+ getOperationCode();
  }

  public boolean equals(Object o){
    if(! (o instanceof ResourceOperationContext))
      return false;

    ResourceOperationContext other = (ResourceOperationContext)o;
    return (this.resource==other.getResource() && this.operation==other.getOperationCode());
  }

  @Override
  public boolean implies(Permission p) {
    return this.equals(p);
  }
}