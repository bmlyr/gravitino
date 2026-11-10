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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.apache.gravitino.credential.AwsEksPodIdentityCredential;
import org.apache.gravitino.credential.CredentialContext;
import org.apache.gravitino.credential.CredentialGenerator;
import org.apache.gravitino.credential.PathBasedCredentialContext;
import org.apache.gravitino.credential.RoleSessionNameUtils;
import org.apache.gravitino.credential.config.S3CredentialConfig;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.policybuilder.iam.IamConditionOperator;
import software.amazon.awssdk.policybuilder.iam.IamEffect;
import software.amazon.awssdk.policybuilder.iam.IamPolicy;
import software.amazon.awssdk.policybuilder.iam.IamResource;
import software.amazon.awssdk.policybuilder.iam.IamStatement;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.Credentials;
import software.amazon.awssdk.utils.SdkAutoCloseable;

/**
 * Generate AWS EKS Pod Identity credentials according to the read and write paths.
 *
 * <p>The credentials that the EKS Pod Identity agent hands to the pod are used to call {@code
 * AssumeRole} on the role configured by {@code s3-role-arn}, with a session policy restricted to
 * the requested locations.
 */
public class AwsEksPodIdentityCredentialGenerator
    implements CredentialGenerator<AwsEksPodIdentityCredential> {

  @VisibleForTesting static final String ROLE_SESSION_NAME_PREFIX = "gravitino_eks_pod_identity_";

  /**
   * EKS Pod Identity credentials are role session credentials, so assuming another role with them
   * is role chaining, which AWS STS limits to one hour.
   */
  @VisibleForTesting static final int MAX_ROLE_CHAINING_DURATION_SECS = 3600;

  private final Supplier<AwsCredentialsProvider> baseCredentialsProviderSupplier;
  private AwsCredentialsProvider baseCredentialsProvider;
  private String roleArn;
  private int tokenExpireSecs;
  private String region;
  private String stsEndpoint;
  private String externalID;
  private boolean listLocationPrefix;

  /** Creates an AWS EKS Pod Identity credential generator. */
  public AwsEksPodIdentityCredentialGenerator() {
    this(() -> ContainerCredentialsProvider.builder().build());
  }

  @VisibleForTesting
  AwsEksPodIdentityCredentialGenerator(
      Supplier<AwsCredentialsProvider> baseCredentialsProviderSupplier) {
    this.baseCredentialsProviderSupplier = Objects.requireNonNull(baseCredentialsProviderSupplier);
  }

  @Override
  public void initialize(Map<String, String> properties) {
    S3CredentialConfig s3CredentialConfig = new S3CredentialConfig(properties);
    this.roleArn = validateRoleArn(properties.get(S3CredentialConfig.S3_ROLE_ARN.getKey()));
    this.tokenExpireSecs = validateTokenExpireSecs(s3CredentialConfig.tokenExpireInSecs());
    this.region = s3CredentialConfig.region();
    this.stsEndpoint = s3CredentialConfig.stsEndpoint();
    this.externalID = s3CredentialConfig.externalID();
    this.listLocationPrefix = s3CredentialConfig.listLocationPrefix();

    this.baseCredentialsProvider = baseCredentialsProviderSupplier.get();
  }

  @Override
  public AwsEksPodIdentityCredential generate(CredentialContext context) {
    if (!(context instanceof PathBasedCredentialContext)) {
      // Without paths there is nothing to scope a session policy to, and the pod's own
      // credentials must never be handed out.
      return null;
    }

    PathBasedCredentialContext pathBasedCredentialContext = (PathBasedCredentialContext) context;
    Set<String> readLocations = pathBasedCredentialContext.getReadPaths();
    Set<String> writeLocations = pathBasedCredentialContext.getWritePaths();
    String userName = pathBasedCredentialContext.getUserName();
    validateInputParameters(readLocations, writeLocations, userName);

    IamPolicy sessionPolicy = createSessionPolicy(readLocations, writeLocations);
    Credentials s3Token = assumeRoleWithSessionPolicy(userName, sessionPolicy);
    return new AwsEksPodIdentityCredential(
        s3Token.accessKeyId(),
        s3Token.secretAccessKey(),
        s3Token.sessionToken(),
        s3Token.expiration().toEpochMilli());
  }

  @Override
  public void close() throws IOException {
    if (baseCredentialsProvider instanceof SdkAutoCloseable) {
      ((SdkAutoCloseable) baseCredentialsProvider).close();
    }
  }

  @VisibleForTesting
  IamPolicy createSessionPolicy(Set<String> readLocations, Set<String> writeLocations) {
    IamPolicy.Builder policyBuilder = IamPolicy.builder();
    String arnPrefix = getArnPrefix(region);

    addReadPermissions(policyBuilder, readLocations, writeLocations, arnPrefix);
    if (!writeLocations.isEmpty()) {
      addWritePermissions(policyBuilder, writeLocations, arnPrefix);
    }
    addBucketPermissions(policyBuilder, readLocations, writeLocations, arnPrefix);

    return policyBuilder.build();
  }

  private static String validateRoleArn(String configRoleArn) {
    Preconditions.checkArgument(
        StringUtils.isNotBlank(configRoleArn),
        "%s is required for the %s credential provider",
        S3CredentialConfig.S3_ROLE_ARN.getKey(),
        AwsEksPodIdentityCredential.AWS_EKS_POD_IDENTITY_CREDENTIAL_TYPE);
    Preconditions.checkArgument(
        configRoleArn.startsWith("arn:aws"), "Invalid role ARN format: %s", configRoleArn);
    return configRoleArn;
  }

  private static int validateTokenExpireSecs(int tokenExpireSecs) {
    Preconditions.checkArgument(
        tokenExpireSecs <= MAX_ROLE_CHAINING_DURATION_SECS,
        "%s must not exceed %s for the %s credential provider, because assuming a role with Pod "
            + "Identity credentials is role chaining, got: %s",
        S3CredentialConfig.S3_TOKEN_EXPIRE_IN_SECS.getKey(),
        MAX_ROLE_CHAINING_DURATION_SECS,
        AwsEksPodIdentityCredential.AWS_EKS_POD_IDENTITY_CREDENTIAL_TYPE,
        tokenExpireSecs);
    return tokenExpireSecs;
  }

  private void addReadPermissions(
      IamPolicy.Builder policyBuilder,
      Set<String> readLocations,
      Set<String> writeLocations,
      String arnPrefix) {
    IamStatement.Builder allowGetObjectStatementBuilder =
        IamStatement.builder()
            .effect(IamEffect.ALLOW)
            .addAction("s3:GetObject")
            .addAction("s3:GetObjectVersion");

    Stream.concat(readLocations.stream(), writeLocations.stream())
        .distinct()
        .forEach(
            location -> {
              URI uri = URI.create(location);
              allowGetObjectStatementBuilder.addResource(
                  IamResource.create(getS3UriWithArn(arnPrefix, uri)));
            });

    policyBuilder.addStatement(allowGetObjectStatementBuilder.build());
  }

  private void addWritePermissions(
      IamPolicy.Builder policyBuilder, Set<String> writeLocations, String arnPrefix) {
    IamStatement.Builder allowPutObjectStatementBuilder =
        IamStatement.builder()
            .effect(IamEffect.ALLOW)
            .addAction("s3:PutObject")
            .addAction("s3:DeleteObject");

    writeLocations.forEach(
        location -> {
          URI uri = URI.create(location);
          allowPutObjectStatementBuilder.addResource(
              IamResource.create(getS3UriWithArn(arnPrefix, uri)));
        });

    policyBuilder.addStatement(allowPutObjectStatementBuilder.build());
  }

  private void addBucketPermissions(
      IamPolicy.Builder policyBuilder,
      Set<String> readLocations,
      Set<String> writeLocations,
      String arnPrefix) {
    Map<String, IamStatement.Builder> bucketListStatementBuilder = new HashMap<>();
    Map<String, IamStatement.Builder> bucketGetLocationStatementBuilder = new HashMap<>();

    Stream.concat(readLocations.stream(), writeLocations.stream())
        .distinct()
        .forEach(
            location -> {
              URI uri = URI.create(location);
              String bucketArn = arnPrefix + getBucketName(uri);
              String rawPath = trimLeadingSlash(uri.getPath());

              bucketListStatementBuilder
                  .computeIfAbsent(
                      bucketArn,
                      key ->
                          IamStatement.builder()
                              .effect(IamEffect.ALLOW)
                              .addAction("s3:ListBucket")
                              .addResource(key))
                  .addConditions(
                      IamConditionOperator.STRING_LIKE,
                      "s3:prefix",
                      AwsIrsaCredentialGenerator.listPrefixes(rawPath, listLocationPrefix));

              bucketGetLocationStatementBuilder.computeIfAbsent(
                  bucketArn,
                  key ->
                      IamStatement.builder()
                          .effect(IamEffect.ALLOW)
                          .addAction("s3:GetBucketLocation")
                          .addResource(key));
            });

    addStatementsToPolicy(policyBuilder, bucketListStatementBuilder);
    addStatementsToPolicy(policyBuilder, bucketGetLocationStatementBuilder);
  }

  private void addStatementsToPolicy(
      IamPolicy.Builder policyBuilder, Map<String, IamStatement.Builder> statementBuilders) {
    statementBuilders.values().forEach(builder -> policyBuilder.addStatement(builder.build()));
  }

  private String getS3UriWithArn(String arnPrefix, URI uri) {
    return arnPrefix
        + addWildcardToPath(getBucketName(uri) + "/" + trimLeadingSlash(uri.getPath()));
  }

  private String getArnPrefix(String region) {
    if (StringUtils.isNotBlank(region)) {
      if (region.contains("cn-")) {
        return "arn:aws-cn:s3:::";
      } else if (region.contains("us-gov-")) {
        return "arn:aws-us-gov:s3:::";
      }
    }
    return "arn:aws:s3:::";
  }

  private static String addWildcardToPath(String path) {
    return path.endsWith("/") ? path + "*" : path + "/*";
  }

  private static String trimLeadingSlash(String path) {
    return path.startsWith("/") ? path.substring(1) : path;
  }

  private static String getBucketName(URI uri) {
    // URI#getHost returns null for bucket names that are not valid hostnames (e.g. with '_'),
    // which would silently produce a policy that grants nothing.
    String bucket = uri.getAuthority();
    Preconditions.checkArgument(
        StringUtils.isNotBlank(bucket), "Cannot resolve the S3 bucket from location: %s", uri);
    return bucket;
  }

  private void validateInputParameters(
      Set<String> readLocations, Set<String> writeLocations, String userName) {
    if (StringUtils.isBlank(userName)) {
      throw new IllegalArgumentException("userName cannot be null or empty");
    }
    if ((readLocations == null || readLocations.isEmpty())
        && (writeLocations == null || writeLocations.isEmpty())) {
      throw new IllegalArgumentException("At least one read or write location must be specified");
    }
  }

  private Credentials assumeRoleWithSessionPolicy(String userName, IamPolicy sessionPolicy) {
    try (StsClient stsClient = createStsClient()) {
      AssumeRoleRequest.Builder requestBuilder =
          AssumeRoleRequest.builder()
              .roleArn(roleArn)
              .roleSessionName(RoleSessionNameUtils.create(ROLE_SESSION_NAME_PREFIX, userName))
              .durationSeconds(tokenExpireSecs)
              .policy(sessionPolicy.toJson());
      if (StringUtils.isNotBlank(externalID)) {
        requestBuilder.externalId(externalID);
      }
      return stsClient.assumeRole(requestBuilder.build()).credentials();
    }
  }

  private StsClient createStsClient() {
    StsClientBuilder stsBuilder = StsClient.builder().credentialsProvider(baseCredentialsProvider);
    if (StringUtils.isNotBlank(region)) {
      stsBuilder.region(Region.of(region));
    }
    if (StringUtils.isNotBlank(stsEndpoint)) {
      stsBuilder.endpointOverride(URI.create(stsEndpoint));
    }
    return stsBuilder.build();
  }
}
