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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.gravitino.credential.AwsEksPodIdentityCredential;
import org.apache.gravitino.credential.PathBasedCredentialContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.policybuilder.iam.IamPolicy;
import software.amazon.awssdk.policybuilder.iam.IamResource;
import software.amazon.awssdk.policybuilder.iam.IamStatement;

class TestAwsEksPodIdentityCredentialGenerator {

  private HttpServer server;
  private AtomicReference<String> requestBody;
  private AtomicReference<String> securityTokenHeader;
  private AtomicInteger requestCount;

  @BeforeEach
  void setUp() throws IOException {
    requestBody = new AtomicReference<>();
    securityTokenHeader = new AtomicReference<>();
    requestCount = new AtomicInteger();
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", this::handleAssumeRole);
    server.start();
  }

  @AfterEach
  void tearDown() {
    server.stop(0);
  }

  @Test
  void catalogRequestDoesNotVendUnscopedCredentials() throws IOException {
    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      generator.initialize(createProperties());
      assertNull(generator.generate(() -> "test-user"));
    }
    assertEquals(0, requestCount.get());
  }

  @Test
  void pathRequestAssumesRoleWithEksPodIdentityCredentialsAndSessionPolicy() throws IOException {
    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      generator.initialize(createProperties());

      AwsEksPodIdentityCredential credential = generator.generate(pathContext("test-user"));

      assertEquals("access-key", credential.accessKeyId());
      assertEquals("secret-key", credential.secretAccessKey());
      assertEquals("session-token", credential.sessionToken());
      assertTrue(credential.expireTimeInMs() > System.currentTimeMillis());
    }

    String body = decodedRequestBody();
    assertTrue(body.contains("Action=AssumeRole"));
    assertTrue(body.contains("RoleArn=arn:aws:iam::123456789012:role/test-role"));
    assertTrue(body.contains("RoleSessionName=gravitino_eks_pod_identity_test-user"));
    assertTrue(body.contains("DurationSeconds=3600"));
    assertTrue(body.contains("Policy="));
    assertFalse(body.contains("ExternalId="));
    // The request is signed with the credentials handed to the pod.
    assertEquals("pod-session-token", securityTokenHeader.get());
    assertEquals(1, requestCount.get());
  }

  @Test
  void externalIdIsPassedWhenConfigured() throws IOException {
    Map<String, String> properties = createProperties();
    properties.put("s3-external-id", "external-id");

    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      generator.initialize(properties);
      generator.generate(pathContext("test-user"));
    }

    assertTrue(decodedRequestBody().contains("ExternalId=external-id"));
  }

  @Test
  void roleSessionNameIsValidForLongOrUnusualUserNames() throws IOException {
    String userName = "hive/host.example.com:spark user " + StringUtils.repeat("a", 100);

    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      generator.initialize(createProperties());
      generator.generate(pathContext(userName));
    }

    String sessionName =
        StringUtils.substringBefore(
            StringUtils.substringAfter(decodedRequestBody(), "RoleSessionName="), "&");
    assertTrue(sessionName.matches("[\\w+=,.@-]{2,64}"), sessionName);
  }

  @Test
  void initializeFailsWhenRoleArnIsMissingOrInvalid() throws IOException {
    Map<String, String> missing = createProperties();
    missing.remove("s3-role-arn");
    Map<String, String> blank = createProperties();
    blank.put("s3-role-arn", " ");
    Map<String, String> invalid = createProperties();
    invalid.put("s3-role-arn", "not-an-arn");

    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      IllegalArgumentException exception =
          assertThrows(IllegalArgumentException.class, () -> generator.initialize(missing));
      assertTrue(exception.getMessage().contains("s3-role-arn is required"));
      assertThrows(IllegalArgumentException.class, () -> generator.initialize(blank));
      assertThrows(IllegalArgumentException.class, () -> generator.initialize(invalid));
    }
  }

  @Test
  void initializeFailsWhenExpirationExceedsRoleChainingLimit() throws IOException {
    Map<String, String> properties = createProperties();
    properties.put("s3-token-expire-in-secs", "7200");

    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      IllegalArgumentException exception =
          assertThrows(IllegalArgumentException.class, () -> generator.initialize(properties));
      assertTrue(exception.getMessage().contains("role chaining"));
    }
  }

  @Test
  void generateFailsWithoutLocations() throws IOException {
    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      generator.initialize(createProperties());
      PathBasedCredentialContext context =
          new PathBasedCredentialContext(
              "test-user", Collections.emptySet(), Collections.emptySet());

      assertThrows(IllegalArgumentException.class, () -> generator.generate(context));
    }
    assertEquals(0, requestCount.get());
  }

  @Test
  void sessionPolicyForReadOnlyLocation() throws IOException {
    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      generator.initialize(createProperties());

      IamPolicy policy =
          generator.createSessionPolicy(
              Collections.singleton("s3://bucket/warehouse/tbl"), Collections.emptySet());

      assertEquals(
          Collections.singletonList("arn:aws:s3:::bucket/warehouse/tbl/*"),
          resourcesForAction(policy, "s3:GetObject"));
      assertTrue(resourcesForAction(policy, "s3:PutObject").isEmpty());
      assertTrue(resourcesForAction(policy, "s3:DeleteObject").isEmpty());
      assertEquals(
          Collections.singletonList("arn:aws:s3:::bucket"),
          resourcesForAction(policy, "s3:ListBucket"));
      assertEquals(
          Collections.singletonList("arn:aws:s3:::bucket"),
          resourcesForAction(policy, "s3:GetBucketLocation"));
    }
  }

  @Test
  void sessionPolicyForWriteLocation() throws IOException {
    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      generator.initialize(createProperties());

      IamPolicy policy =
          generator.createSessionPolicy(
              Collections.emptySet(), Collections.singleton("s3://bucket/warehouse/tbl/"));

      List<String> expected = Collections.singletonList("arn:aws:s3:::bucket/warehouse/tbl/*");
      assertEquals(expected, resourcesForAction(policy, "s3:GetObject"));
      assertEquals(expected, resourcesForAction(policy, "s3:PutObject"));
      assertEquals(expected, resourcesForAction(policy, "s3:DeleteObject"));
    }
  }

  @Test
  void sessionPolicyKeepsBucketNameThatIsNotAValidHostname() throws IOException {
    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      generator.initialize(createProperties());

      IamPolicy policy =
          generator.createSessionPolicy(
              Collections.singleton("s3://my_bucket/warehouse/tbl"), Collections.emptySet());

      assertEquals(
          Collections.singletonList("arn:aws:s3:::my_bucket/warehouse/tbl/*"),
          resourcesForAction(policy, "s3:GetObject"));
      assertEquals(
          Collections.singletonList("arn:aws:s3:::my_bucket"),
          resourcesForAction(policy, "s3:ListBucket"));
    }
  }

  @Test
  void sessionPolicyUsesPartitionOfRegion() throws IOException {
    Map<String, String> properties = createProperties();
    properties.put("s3-region", "cn-north-1");
    properties.put("s3-role-arn", "arn:aws-cn:iam::123456789012:role/test-role");

    try (AwsEksPodIdentityCredentialGenerator generator = newGenerator()) {
      generator.initialize(properties);

      IamPolicy policy =
          generator.createSessionPolicy(
              Collections.singleton("s3://bucket/tbl"), Collections.emptySet());

      assertEquals(
          Collections.singletonList("arn:aws-cn:s3:::bucket/tbl/*"),
          resourcesForAction(policy, "s3:GetObject"));
    }
  }

  private static AwsEksPodIdentityCredentialGenerator newGenerator() {
    AwsCredentialsProvider podCredentials =
        StaticCredentialsProvider.create(
            AwsSessionCredentials.create("pod-access-key", "pod-secret-key", "pod-session-token"));
    return new AwsEksPodIdentityCredentialGenerator(() -> podCredentials);
  }

  private Map<String, String> createProperties() {
    Map<String, String> properties = new HashMap<>();
    properties.put("s3-role-arn", "arn:aws:iam::123456789012:role/test-role");
    properties.put("s3-region", "us-east-1");
    properties.put(
        "s3-token-service-endpoint",
        String.format("http://127.0.0.1:%s", server.getAddress().getPort()));
    return properties;
  }

  private static PathBasedCredentialContext pathContext(String userName) {
    return new PathBasedCredentialContext(
        userName, Collections.emptySet(), Collections.singleton("s3://bucket/object"));
  }

  private String decodedRequestBody() throws IOException {
    return URLDecoder.decode(requestBody.get(), StandardCharsets.UTF_8.name());
  }

  private static List<String> resourcesForAction(IamPolicy policy, String action) {
    return policy.statements().stream()
        .filter(statement -> statement.actions().stream().anyMatch(a -> a.value().equals(action)))
        .map(IamStatement::resources)
        .flatMap(List::stream)
        .map(IamResource::value)
        .sorted()
        .collect(Collectors.toList());
  }

  private void handleAssumeRole(HttpExchange exchange) throws IOException {
    requestCount.incrementAndGet();
    requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
    securityTokenHeader.set(exchange.getRequestHeaders().getFirst("X-Amz-Security-Token"));
    byte[] response =
        ("<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">"
                + "<AssumeRoleResult><Credentials>"
                + "<AccessKeyId>access-key</AccessKeyId>"
                + "<SecretAccessKey>secret-key</SecretAccessKey>"
                + "<SessionToken>session-token</SessionToken>"
                + "<Expiration>"
                + Instant.now().plusSeconds(3600)
                + "</Expiration>"
                + "</Credentials></AssumeRoleResult>"
                + "</AssumeRoleResponse>")
            .getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(200, response.length);
    exchange.getResponseBody().write(response);
    exchange.close();
  }
}
