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
package org.codice.ddf.security.oauth.interceptor;

import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.codice.gsonsupport.GsonTypeAdapters.MAP_STRING_TO_OBJECT_TYPE;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import ddf.security.Subject;
import ddf.security.SubjectUtils;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.util.Base64;
import java.util.Map;
import javax.ws.rs.core.Form;
import org.apache.commons.io.IOUtils;
import org.apache.cxf.jaxrs.client.Client;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.util.Strings;
import org.codice.ddf.security.oidc.validator.OidcTokenValidator;
import org.codice.ddf.security.oidc.validator.OidcValidationException;
import org.codice.ddf.security.token.storage.api.TokenInformation;
import org.codice.ddf.security.token.storage.api.TokenStorage;
import org.codice.gsonsupport.GsonTypeAdapters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthSecurityImpl implements OAuthSecurity {

  private static final Logger LOGGER = LoggerFactory.getLogger(OAuthSecurityImpl.class);

  static final Gson GSON =
      new GsonBuilder()
          .disableHtmlEscaping()
          .registerTypeAdapterFactory(GsonTypeAdapters.LongDoubleTypeAdapter.FACTORY)
          .create();

  private static final String BASIC = "Basic ";
  private static final String BEARER = "Bearer ";
  private static final String ID_TOKEN = "id_token";
  private static final String GRANT_TYPE = "grant_type";
  private static final String ACCESS_TOKEN = "access_token";
  private static final String CLIENT_CREDENTIALS = "client_credentials";

  private ResourceRetriever resourceRetriever;
  private TokenStorage tokenStorage;

  public OAuthSecurityImpl(TokenStorage tokenStorage) {
    this.tokenStorage = tokenStorage;
    resourceRetriever = new DefaultResourceRetriever();
  }

  /**
   * Retrieves the system's access token from the configured OAuth provider and sets it to the OAUTH
   * header
   *
   * @param client Non-null client to set the access token on.
   * @param clientId The client ID registered with the OAuth provider
   * @param clientSecret The client secret registered with the OAuth provider
   * @param discoveryUrl the metadata URL of the OAuth provider
   */
  public void setSystemTokenOnClient(
      Client client, String clientId, String clientSecret, String discoveryUrl) {
    if (client == null
        || Strings.isBlank(clientId)
        || Strings.isBlank(clientSecret)
        || Strings.isBlank(discoveryUrl)) {
      return;
    }

    OIDCProviderMetadata metadata;
    try {
      metadata =
          OIDCProviderMetadata.parse(
              resourceRetriever.retrieveResource(new URL(discoveryUrl)).getContent());
    } catch (IOException | ParseException e) {
      LOGGER.error("Unable to retrieve OAuth provider's metadata.", e);
      return;
    }

    WebClient webClient = createWebClient(metadata.getTokenEndpointURI());
    String encodedClientIdSecret =
        Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes(UTF_8));

    webClient.header(AUTHORIZATION, BASIC + encodedClientIdSecret);
    webClient.accept(APPLICATION_JSON);

    Form formParam = new Form(GRANT_TYPE, CLIENT_CREDENTIALS);
    javax.ws.rs.core.Response response = webClient.form(formParam);

    String body;
    try {
      body = IOUtils.toString((InputStream) response.getEntity(), UTF_8);
    } catch (IOException e) {
      LOGGER.debug("Unable to retrieve system access token.", e);
      return;
    }

    if (response.getStatus() != HttpStatus.SC_OK) {
      LOGGER.debug("Unable to retrieve system access token. {}", body);
      return;
    }

    Map<String, String> map = GSON.fromJson(body, MAP_STRING_TO_OBJECT_TYPE);
    String idToken = map.get(ID_TOKEN);
    String accessToken = map.get(ACCESS_TOKEN);

    JWT jwt = null;
    try {
      if (idToken != null) {
        jwt = SignedJWT.parse(idToken);
      }
    } catch (java.text.ParseException e) {
      LOGGER.debug("Error parsing ID token.", e);
    }

    try {
      OidcTokenValidator.validateAccessToken(
          new BearerAccessToken(accessToken), jwt, resourceRetriever, metadata, null);
    } catch (OidcValidationException e) {
      LOGGER.warn("Error validating system access token.", e);
      return;
    }

    LOGGER.debug("Successfully retrieved system access token. Adding to OAUTH header.");
    client.header(OAUTH, BEARER + accessToken);
  }

  /**
   * Gets the user's access token from the token storage to set it to the OAUTH header.
   *
   * @param client Non-null client to set the access token on.
   * @param subject subject used to get the user's id (email or username)
   * @param sourceId the id of the source using OAuth needed to get the correct tokens
   */
  public void setUserTokenOnClient(Client client, Subject subject, String sourceId) {
    if (client == null || subject == null || Strings.isBlank(sourceId)) {
      return;
    }

    String userId = SubjectUtils.getEmailAddress(subject);
    if (userId == null) {
      userId = SubjectUtils.getName(subject);
    }

    TokenInformation.TokenEntry tokenEntry = tokenStorage.read(userId, sourceId);
    if (tokenEntry == null) {
      LOGGER.debug("Unable to find user's token to set on client.");
      return;
    }

    LOGGER.debug("Adding access token to OAUTH header.");
    client.header(OAUTH, BEARER + tokenEntry.getAccessToken());
  }

  @VisibleForTesting
  WebClient createWebClient(URI uri) {
    return WebClient.create(uri);
  }

  @VisibleForTesting
  void setResourceRetriever(ResourceRetriever resourceRetriever) {
    this.resourceRetriever = resourceRetriever;
  }
}
