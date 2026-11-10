/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.gravitino.s3.credential;

import org.apache.gravitino.credential.AwsEksPodIdentityCredential;
import org.apache.gravitino.credential.CredentialProviderDelegator;

/**
 * AWS EKS Pod Identity credential provider that vends path-scoped S3 credentials.
 *
 * <p>For path-based credential contexts (e.g., table access with vended credentials), the provider
 * uses the credentials that the EKS Pod Identity agent hands to the Gravitino pod to call {@code
 * AssumeRole} on the role configured by {@code s3-role-arn}, with a session policy restricted to
 * the requested S3 paths. Session policies can only reduce (not expand) the permissions already
 * granted by that role.
 *
 * <p>Catalog-level requests vend nothing: they provide no paths to scope a session policy to, and
 * the pod's own credentials are never handed out.
 *
 * <p>Prerequisites:
 *
 * <ul>
 *   <li>EKS cluster with the EKS Pod Identity agent installed, and an EKS Pod Identity association
 *       for the Kubernetes service account of the Gravitino pod
 *   <li>{@code s3-role-arn} set to the role to assume
 *   <li>That role's trust policy allows both {@code sts:AssumeRole} and {@code sts:TagSession} from
 *       the EKS Pod Identity role, because EKS Pod Identity credentials carry transitive session
 *       tags
 *   <li>Optional: {@code s3-external-id} when that trust policy requires an external ID
 * </ul>
 */
public class AwsEksPodIdentityCredentialProvider
    extends CredentialProviderDelegator<AwsEksPodIdentityCredential> {

  @Override
  public boolean supportsScheme(String scheme) {
    return "s3".equalsIgnoreCase(scheme)
        || "s3a".equalsIgnoreCase(scheme)
        || "s3n".equalsIgnoreCase(scheme);
  }

  @Override
  public String credentialType() {
    return AwsEksPodIdentityCredential.AWS_EKS_POD_IDENTITY_CREDENTIAL_TYPE;
  }

  @Override
  public String getGeneratorClassName() {
    return "org.apache.gravitino.s3.credential.AwsEksPodIdentityCredentialGenerator";
  }
}
