/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.ddf.catalog.plugin.oauth;

import static ddf.catalog.plugin.OAuthPluginException.ErrorType.AUTH_SOURCE;
import static ddf.catalog.plugin.OAuthPluginException.ErrorType.NO_AUTH;
import static ddf.security.SecurityConstants.SECURITY_SUBJECT;
import static org.codice.ddf.catalog.plugin.oauth.OAuthPlugin.GSON;
import static org.codice.ddf.security.token.storage.api.TokenStorage.CLIENT_ID;
import static org.codice.ddf.security.token.storage.api.TokenStorage.DISCOVERY_URL;
import static org.codice.ddf.security.token.storage.api.TokenStorage.SECRET;
import static org.codice.ddf.security.token.storage.api.TokenStorage.SOURCE_ID;
import static org.codice.ddf.security.token.storage.api.TokenStorage.USER_ID;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.pac4j.core.context.HttpConstants.APPLICATION_JSON;
import static org.pac4j.oidc.profile.OidcProfileDefinition.AZP;
import static org.pac4j.oidc.profile.OidcProfileDefinition.EMAIL_VERIFIED;
import static org.pac4j.oidc.profile.OidcProfileDefinition.PREFERRED_USERNAME;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import ddf.catalog.operation.QueryRequest;
import ddf.catalog.plugin.OAuthPluginException;
import ddf.catalog.source.OAuthFederatedSource;
import ddf.security.Subject;
import ddf.security.assertion.SecurityAssertion;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.apache.commons.io.IOUtils;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.codice.ddf.security.file.token.storage.TokenInformationImpl;
import org.codice.ddf.security.token.storage.api.TokenInformation;
import org.codice.ddf.security.token.storage.api.TokenStorage;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

public class OAuthPluginTest {

  private static final String USERNAME = "admin";
  private static final String DDF_CLIENT = "ddf-client";
  private static final String DDF_SECRET = "secret";
  private static final String MY_SOURCE_ID = "CSW";
  private static final String METADATA_ENDPOINT = "http://localhost:8080/auth/master/metadata";
  private static final String JWK_ENDPOINT =
      "http://localhost:8080/auth/realms/master/protocol/openid-connect/certs";
  private static final String AUTH_ENDPOINT =
      "http://localhost:8080/auth/realms/master/protocol/openid-connect/auth";
  private static final String OAUTH_ENDPOINT =
      "https://localhost:8993/search/catalog/internal/oauth/auth";

  private Algorithm validAlgorithm;
  private Algorithm invalidAlgorithm;
  private TokenStorage tokenStorage;
  private OAuthPluginWithMockWebclient oauthPlugin;

  @Before
  public void setUp() throws Exception {
    // Generate the RSA key pair to sign tokens
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    gen.initialize(2048);
    KeyPair keyPair = gen.generateKeyPair();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

    JWK sigJwk =
        new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .build();

    String jwk = "{\"keys\": [" + sigJwk.toPublicJWK().toJSONString() + "] }";
    validAlgorithm = Algorithm.RSA256(publicKey, privateKey);
    invalidAlgorithm = Algorithm.HMAC256("WRONG");

    ResourceRetriever resourceRetriever = mock(ResourceRetriever.class);
    Resource jwkResource = new Resource(jwk, APPLICATION_JSON);
    when(resourceRetriever.retrieveResource(eq(new URL(JWK_ENDPOINT)))).thenReturn(jwkResource);

    String content =
        IOUtils.toString(
            Objects.requireNonNull(
                getClass().getClassLoader().getResourceAsStream("metadata.json")),
            StandardCharsets.UTF_8);
    Resource metadataResource = new Resource(content, APPLICATION_JSON);
    when(resourceRetriever.retrieveResource(eq(new URL(METADATA_ENDPOINT))))
        .thenReturn(metadataResource);

    tokenStorage = mock(TokenStorage.class);
    oauthPlugin = new OAuthPluginWithMockWebclient(tokenStorage);
    oauthPlugin.setResourceRetriever(resourceRetriever);
  }

  @Test
  public void testProcessCredentialFlow() throws Exception {
    QueryRequest input = mock(QueryRequest.class);
    OAuthFederatedSource source = mock(OAuthFederatedSource.class);
    when(source.isUseOauth()).thenReturn(true);
    when(source.getOauthFlow()).thenReturn("credential");

    QueryRequest request = oauthPlugin.process(source, input);
    assertEquals(input, request);
  }

  @Test
  public void testProcessExistingUser() throws Exception {
    Subject subject = getMockSubject();
    QueryRequest input = mock(QueryRequest.class);
    when(input.getProperties()).thenReturn(ImmutableMap.of(SECURITY_SUBJECT, subject));

    OAuthFederatedSource source = mock(OAuthFederatedSource.class);
    when(source.isUseOauth()).thenReturn(true);
    when(source.getOauthDiscoveryUrl()).thenReturn(METADATA_ENDPOINT);
    when(source.getOauthClientId()).thenReturn(DDF_CLIENT);
    when(source.getOauthClientSecret()).thenReturn(DDF_SECRET);
    when(source.getOauthFlow()).thenReturn("code");
    when(source.getId()).thenReturn(MY_SOURCE_ID);

    String accessToken = getAccessTokenBuilder().sign(validAlgorithm);
    String refreshToken = getRefreshTokenBuilder().sign(validAlgorithm);

    TokenInformation.TokenEntry tokenEntry =
        new TokenInformationImpl.TokenEntryImpl(accessToken, refreshToken, METADATA_ENDPOINT);
    when(tokenStorage.read(USERNAME, MY_SOURCE_ID)).thenReturn(tokenEntry);

    QueryRequest request = oauthPlugin.process(source, input);
    assertEquals(input, request);
  }

  @Test
  public void testProcessExistingUserExpiredAccessToken() throws Exception {
    Subject subject = getMockSubject();
    QueryRequest input = mock(QueryRequest.class);
    when(input.getProperties()).thenReturn(ImmutableMap.of(SECURITY_SUBJECT, subject));

    OAuthFederatedSource source = mock(OAuthFederatedSource.class);
    when(source.isUseOauth()).thenReturn(true);
    when(source.getOauthDiscoveryUrl()).thenReturn(METADATA_ENDPOINT);
    when(source.getOauthClientId()).thenReturn(DDF_CLIENT);
    when(source.getOauthClientSecret()).thenReturn(DDF_SECRET);
    when(source.getOauthFlow()).thenReturn("code");
    when(source.getId()).thenReturn(MY_SOURCE_ID);

    String accessToken =
        getAccessTokenBuilder()
            .withExpiresAt(new Date(Instant.now().minus(Duration.ofDays(3)).toEpochMilli()))
            .sign(validAlgorithm);
    String refreshToken = getRefreshTokenBuilder().sign(validAlgorithm);

    TokenInformation.TokenEntry tokenEntry =
        new TokenInformationImpl.TokenEntryImpl(accessToken, refreshToken, METADATA_ENDPOINT);
    when(tokenStorage.read(USERNAME, MY_SOURCE_ID)).thenReturn(tokenEntry);

    WebClient webClient = oauthPlugin.webClient;
    Response response = mock(Response.class);
    when(response.getStatus()).thenReturn(200);
    when(response.getEntity())
        .thenReturn(new ByteArrayInputStream(getRefreshResponse(true).getBytes()));
    when(webClient.form(any(Form.class))).thenReturn(response);

    oauthPlugin.process(source, input);
    ArgumentCaptor<Form> captor = ArgumentCaptor.forClass(Form.class);
    verify(webClient, times(1)).form(captor.capture());
    verify(tokenStorage, times(1))
        .create(anyString(), anyString(), anyString(), anyString(), anyString());

    Form form = captor.getValue();
    MultivaluedMap<String, String> map = form.asMap();
    assertTrue(map.get("grant_type").contains("refresh_token"));
    assertTrue(map.get("refresh_token").contains(refreshToken));
  }

  @Test(expected = OAuthPluginException.class)
  public void testProcessInvalidRefreshedAccessToken() throws Exception {
    Subject subject = getMockSubject();
    QueryRequest input = mock(QueryRequest.class);
    when(input.getProperties()).thenReturn(ImmutableMap.of(SECURITY_SUBJECT, subject));

    OAuthFederatedSource source = mock(OAuthFederatedSource.class);
    when(source.isUseOauth()).thenReturn(true);
    when(source.getOauthDiscoveryUrl()).thenReturn(METADATA_ENDPOINT);
    when(source.getOauthClientId()).thenReturn(DDF_CLIENT);
    when(source.getOauthClientSecret()).thenReturn(DDF_SECRET);
    when(source.getOauthFlow()).thenReturn("code");
    when(source.getId()).thenReturn(MY_SOURCE_ID);

    String accessToken =
        getAccessTokenBuilder()
            .withExpiresAt(new Date(Instant.now().minus(Duration.ofDays(3)).toEpochMilli()))
            .sign(validAlgorithm);
    String refreshToken = getRefreshTokenBuilder().sign(validAlgorithm);

    TokenInformation.TokenEntry tokenEntry =
        new TokenInformationImpl.TokenEntryImpl(accessToken, refreshToken, METADATA_ENDPOINT);
    Map stateMap = mock(Map.class);
    when(tokenStorage.getStateMap()).thenReturn(stateMap);
    when(tokenStorage.read(USERNAME, MY_SOURCE_ID)).thenReturn(tokenEntry);

    WebClient webClient = oauthPlugin.webClient;
    Response response = mock(Response.class);
    when(response.getStatus()).thenReturn(200);
    when(response.getEntity())
        .thenReturn(new ByteArrayInputStream(getRefreshResponse(false).getBytes()));
    when(webClient.form(any(Form.class))).thenReturn(response);

    try {
      oauthPlugin.process(source, input);
    } catch (OAuthPluginException e) {
      ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
      ArgumentCaptor<Map<String, String>> valueCaptor = ArgumentCaptor.forClass(Map.class);
      verify(tokenStorage, times(1)).getStateMap();
      verify(stateMap, times(1)).put(keyCaptor.capture(), valueCaptor.capture());

      Map<String, String> state = valueCaptor.getValue();
      assertEquals(USERNAME, state.get(USER_ID));
      assertEquals(MY_SOURCE_ID, state.get(SOURCE_ID));
      assertEquals(METADATA_ENDPOINT, state.get(DISCOVERY_URL));
      assertEquals(DDF_CLIENT, state.get(CLIENT_ID));
      assertEquals(DDF_SECRET, state.get(SECRET));

      assertEquals(NO_AUTH, e.getErrorType());
      assertEquals(MY_SOURCE_ID, e.getSourceId());
      assertUrl(e.getUrl(), keyCaptor.getValue());
      throw e;
    }
  }

  @Test(expected = OAuthPluginException.class)
  public void testProcessExpiredTokens() throws Exception {
    Subject subject = getMockSubject();
    QueryRequest input = mock(QueryRequest.class);
    when(input.getProperties()).thenReturn(ImmutableMap.of(SECURITY_SUBJECT, subject));

    OAuthFederatedSource source = mock(OAuthFederatedSource.class);
    when(source.isUseOauth()).thenReturn(true);
    when(source.getOauthDiscoveryUrl()).thenReturn(METADATA_ENDPOINT);
    when(source.getOauthClientId()).thenReturn(DDF_CLIENT);
    when(source.getOauthClientSecret()).thenReturn(DDF_SECRET);
    when(source.getOauthFlow()).thenReturn("code");
    when(source.getId()).thenReturn(MY_SOURCE_ID);

    String accessToken =
        getAccessTokenBuilder()
            .withExpiresAt(new Date(Instant.now().minus(Duration.ofDays(3)).toEpochMilli()))
            .sign(validAlgorithm);

    String refreshToken =
        getRefreshTokenBuilder()
            .withExpiresAt(new Date(Instant.now().minus(Duration.ofDays(3)).toEpochMilli()))
            .sign(validAlgorithm);

    TokenInformation.TokenEntry tokenEntry =
        new TokenInformationImpl.TokenEntryImpl(accessToken, refreshToken, METADATA_ENDPOINT);
    Map stateMap = mock(Map.class);
    when(tokenStorage.getStateMap()).thenReturn(stateMap);
    when(tokenStorage.read(USERNAME, MY_SOURCE_ID)).thenReturn(tokenEntry);

    Response response = mock(Response.class);
    when(response.getEntity()).thenReturn(new ByteArrayInputStream("".getBytes()));
    when(response.getStatus()).thenReturn(400);

    WebClient webClient = oauthPlugin.webClient;
    when(webClient.form(any(Form.class))).thenReturn(response);

    try {
      oauthPlugin.process(source, input);
    } catch (OAuthPluginException e) {
      ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
      ArgumentCaptor<Map<String, String>> valueCaptor = ArgumentCaptor.forClass(Map.class);
      verify(tokenStorage, times(1)).getStateMap();
      verify(stateMap, times(1)).put(keyCaptor.capture(), valueCaptor.capture());

      Map<String, String> state = valueCaptor.getValue();
      assertEquals(USERNAME, state.get(USER_ID));
      assertEquals(MY_SOURCE_ID, state.get(SOURCE_ID));
      assertEquals(METADATA_ENDPOINT, state.get(DISCOVERY_URL));
      assertEquals(DDF_CLIENT, state.get(CLIENT_ID));
      assertEquals(DDF_SECRET, state.get(SECRET));

      assertEquals(NO_AUTH, e.getErrorType());
      assertEquals(MY_SOURCE_ID, e.getSourceId());
      assertUrl(e.getUrl(), keyCaptor.getValue());
      throw e;
    }
  }

  @Test(expected = OAuthPluginException.class)
  public void testProcessUnauthorizedSource() throws Exception {
    Subject subject = getMockSubject();
    QueryRequest input = mock(QueryRequest.class);
    when(input.getProperties()).thenReturn(ImmutableMap.of(SECURITY_SUBJECT, subject));

    OAuthFederatedSource source = mock(OAuthFederatedSource.class);
    when(source.isUseOauth()).thenReturn(true);
    when(source.getOauthDiscoveryUrl()).thenReturn(METADATA_ENDPOINT);
    when(source.getOauthClientId()).thenReturn(DDF_CLIENT);
    when(source.getOauthClientSecret()).thenReturn(DDF_SECRET);
    when(source.getOauthFlow()).thenReturn("code");
    when(source.getId()).thenReturn(MY_SOURCE_ID);

    TokenInformation tokenInformation = mock(TokenInformation.class);
    when(tokenInformation.getDiscoveryUrls())
        .thenReturn(ImmutableSet.of("https://someurl.com/", "https://localhost:8993/"));

    Map stateMap = mock(Map.class);
    when(tokenStorage.getStateMap()).thenReturn(stateMap);
    when(tokenStorage.read(USERNAME, MY_SOURCE_ID)).thenReturn(null);
    when(tokenStorage.read(USERNAME)).thenReturn(tokenInformation);

    try {
      oauthPlugin.process(source, input);
    } catch (OAuthPluginException e) {
      ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
      ArgumentCaptor<Map<String, String>> valueCaptor = ArgumentCaptor.forClass(Map.class);
      verify(tokenStorage, times(1)).getStateMap();
      verify(stateMap, times(1)).put(keyCaptor.capture(), valueCaptor.capture());

      Map<String, String> state = valueCaptor.getValue();
      assertEquals(USERNAME, state.get(USER_ID));
      assertEquals(MY_SOURCE_ID, state.get(SOURCE_ID));
      assertEquals(METADATA_ENDPOINT, state.get(DISCOVERY_URL));
      assertEquals(DDF_CLIENT, state.get(CLIENT_ID));
      assertEquals(DDF_SECRET, state.get(SECRET));

      assertEquals(NO_AUTH, e.getErrorType());
      assertEquals(MY_SOURCE_ID, e.getSourceId());
      assertUrl(e.getUrl(), keyCaptor.getValue());
      throw e;
    }
  }

  @Test(expected = OAuthPluginException.class)
  public void testProcessUnauthorizedSourceWithExistingOauthProvider() throws Exception {
    Subject subject = getMockSubject();
    QueryRequest input = mock(QueryRequest.class);
    when(input.getProperties()).thenReturn(ImmutableMap.of(SECURITY_SUBJECT, subject));

    OAuthFederatedSource source = mock(OAuthFederatedSource .class);
    when(source.isUseOauth()).thenReturn(true);
    when(source.getOauthDiscoveryUrl()).thenReturn(METADATA_ENDPOINT);
    when(source.getOauthClientId()).thenReturn(DDF_CLIENT);
    when(source.getOauthClientSecret()).thenReturn(DDF_SECRET);
    when(source.getOauthFlow()).thenReturn("code");
    when(source.getId()).thenReturn(MY_SOURCE_ID);

    TokenInformation tokenInformation = mock(TokenInformation.class);
    when(tokenInformation.getDiscoveryUrls())
        .thenReturn(
            ImmutableSet.of("https://someurl.com/", "https://localhost:8993/", METADATA_ENDPOINT));
    when(tokenStorage.read(USERNAME, MY_SOURCE_ID)).thenReturn(null);
    when(tokenStorage.read(USERNAME)).thenReturn(tokenInformation);

    try {
      oauthPlugin.process(source, input);
    } catch (OAuthPluginException e) {
      assertEquals(AUTH_SOURCE, e.getErrorType());
      assertEquals("CSW", e.getSourceId());
      assertEquals(OAUTH_ENDPOINT, e.getUrl().split("\\?")[0]);
      URI uri = new URI(e.getUrl());
      Map<String, String> params =
          URLEncodedUtils.parse(uri, StandardCharsets.UTF_8)
              .stream()
              .collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));

      assertEquals(USERNAME, params.get(USER_ID));
      assertEquals(MY_SOURCE_ID, params.get(SOURCE_ID));
      assertEquals(METADATA_ENDPOINT, params.get(DISCOVERY_URL));
      throw e;
    }
  }

  private Subject getMockSubject() {
    Principal principal = mock(Principal.class);
    when(principal.getName()).thenReturn(USERNAME);

    SecurityAssertion securityAssertion = mock(SecurityAssertion.class);
    when(securityAssertion.getWeight()).thenReturn(10);
    when(securityAssertion.getPrincipal()).thenReturn(principal);

    PrincipalCollection principalCollection = mock(PrincipalCollection.class);
    when(principalCollection.byType(SecurityAssertion.class))
        .thenReturn(Collections.singletonList(securityAssertion));

    Subject subject = mock(Subject.class);
    when(subject.getPrincipals()).thenReturn(principalCollection);
    return subject;
  }

  private void assertUrl(String url, String stateUuid) throws Exception {
    assertEquals(AUTH_ENDPOINT, url.split("\\?")[0]);

    URI uri = new URI(url);
    Map<String, String> params =
        URLEncodedUtils.parse(uri, StandardCharsets.UTF_8)
            .stream()
            .collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue));

    assertEquals("openid", params.get("scope"));
    assertEquals("code", params.get("response_type"));
    assertEquals(
        "https://localhost:8993/search/catalog/internal/oauth", params.get("redirect_uri"));
    assertEquals(DDF_CLIENT, params.get("client_id"));
    assertEquals(stateUuid, params.get("state"));
  }

  private JWTCreator.Builder getAccessTokenBuilder() {
    String[] audience = {"master-realm", "account"};
    String[] roles = {"create-realm", "offline_access", "admin", "uma_authorization"};

    return com.auth0
        .jwt
        .JWT
        .create()
        .withJWTId(UUID.randomUUID().toString())
        .withExpiresAt(new Date(Instant.now().plus(Duration.ofDays(3)).toEpochMilli()))
        .withNotBefore(new Date(0))
        .withIssuedAt(new Date())
        .withIssuer("http://localhost:8080/auth/realms/master")
        .withArrayClaim("aud", audience)
        .withSubject("subject")
        .withClaim("typ", "Bearer")
        .withClaim(AZP, DDF_CLIENT)
        .withClaim("auth_time", new Date())
        .withArrayClaim("roles", roles)
        .withClaim(EMAIL_VERIFIED, false)
        .withClaim(PREFERRED_USERNAME, "admin");
  }

  private JWTCreator.Builder getRefreshTokenBuilder() {
    long exp = Instant.now().plus(Duration.ofDays(3)).toEpochMilli();
    String[] audience = {"master-realm", "account"};
    JSONObject realmAccess = new JSONObject();
    realmAccess.put(
        "roles", ImmutableList.of("create-realm", "offline_access", "admin", "uma_authorization"));

    return JWT.create()
        .withJWTId(UUID.randomUUID().toString())
        .withExpiresAt(new Date(exp))
        .withNotBefore(new Date(0))
        .withIssuedAt(new Date())
        .withIssuer("http://localhost:8080/auth/realms/master")
        .withAudience("http://localhost:8080/auth/realms/master")
        .withArrayClaim("aud", audience)
        .withSubject("sub")
        .withClaim("typ", "Refresh")
        .withClaim(AZP, DDF_CLIENT)
        .withClaim("auth_time", 0)
        .withClaim("realm_access", realmAccess.toString())
        .withClaim("scope", "openid profile email");
  }

  /**
   * Creates a JSON response after refreshing a token
   *
   * @param validSignature - whether the access token should have a valid signature or not
   */
  private String getRefreshResponse(boolean validSignature) {
    String accessToken;
    if (validSignature) {
      accessToken = getAccessTokenBuilder().sign(validAlgorithm);
    } else {
      accessToken = getAccessTokenBuilder().sign(invalidAlgorithm);
    }

    String refreshToken = getRefreshTokenBuilder().sign(validAlgorithm);

    return GSON.toJson(
        ImmutableMap.of(
            "access_token",
            accessToken,
            "token_type",
            "Bearer",
            "refresh_token",
            refreshToken,
            "expires_in",
            3600));
  }

  /**
   * {@link OAuthPlugin} which uses a mocked Webclient instead of creating a real one for testing
   * purposes
   */
  private static class OAuthPluginWithMockWebclient extends OAuthPlugin {
    WebClient webClient = mock(WebClient.class);

    OAuthPluginWithMockWebclient(TokenStorage tokenStorage) {
      super(tokenStorage);
    }

    @Override
    WebClient createWebclient(String url) {
      return webClient;
    }
  }
}
