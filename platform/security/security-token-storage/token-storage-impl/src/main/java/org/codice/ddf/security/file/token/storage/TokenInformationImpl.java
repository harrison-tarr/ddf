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
package org.codice.ddf.security.file.token.storage;

import static org.codice.ddf.security.token.storage.api.TokenStorage.ACCESS_TOKEN;
import static org.codice.ddf.security.token.storage.api.TokenStorage.DISCOVERY_URL;
import static org.codice.ddf.security.token.storage.api.TokenStorage.REFRESH_TOKEN;
import static org.codice.gsonsupport.GsonTypeAdapters.MAP_STRING_TO_OBJECT_TYPE;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.codice.ddf.security.token.storage.api.TokenInformation;
import org.codice.gsonsupport.GsonTypeAdapters.LongDoubleTypeAdapter;

public class TokenInformationImpl implements TokenInformation {

  static final Gson GSON =
      new GsonBuilder()
          .disableHtmlEscaping()
          .registerTypeAdapterFactory(LongDoubleTypeAdapter.FACTORY)
          .create();

  private Map<String, TokenEntry> tokenEntryList;
  private Set<String> discoveryUrls;
  private String userId;
  private String json;
  private String id;

  private TokenInformationImpl(
      String id,
      String userId,
      Map<String, TokenEntry> tokenEntryList,
      Set<String> discoveryUrls,
      String json) {

    this.id = id;
    this.userId = userId;
    this.tokenEntryList = tokenEntryList;
    this.discoveryUrls = discoveryUrls;
    this.json = json;
  }

  /** Creates a token information from a json representation */
  static TokenInformationImpl fromJson(String id, String userId, String json) {
    Map<String, Object> jsonMap = GSON.fromJson(json, MAP_STRING_TO_OBJECT_TYPE);
    Map<String, TokenEntry> tokenEntryMap = new HashMap<>();
    Set<String> discoveryUrls = new HashSet<>();

    for (Map.Entry<String, Object> sourceVal : jsonMap.entrySet()) {
      Map tokens = (Map) sourceVal.getValue();
      discoveryUrls.add((String) tokens.get(DISCOVERY_URL));
      tokenEntryMap.put(
          sourceVal.getKey(),
          new TokenEntryImpl(
              (String) tokens.get(ACCESS_TOKEN),
              (String) tokens.get(REFRESH_TOKEN),
              (String) tokens.get(DISCOVERY_URL)));
    }

    return new TokenInformationImpl(id, userId, tokenEntryMap, discoveryUrls, json);
  }

  /**
   * @return a Json representation of the given source information and the contents of the given
   *     token information.
   */
  static String getJson(
      TokenInformation tokenInformation,
      String sourceId,
      String accessToken,
      String refreshToken,
      String discoveryUrl) {

    Map<String, Object> jsonMap =
        GSON.fromJson(tokenInformation.getTokenJson(), MAP_STRING_TO_OBJECT_TYPE);

    Map<String, Object> sourceInfoMap = new HashMap<>();
    sourceInfoMap.put(ACCESS_TOKEN, accessToken);
    sourceInfoMap.put(REFRESH_TOKEN, refreshToken);
    sourceInfoMap.put(DISCOVERY_URL, discoveryUrl);
    jsonMap.put(sourceId, sourceInfoMap);

    return GSON.toJson(jsonMap);
  }

  /** @return a Json representation of the given source information */
  static String getJson(
      String sourceId, String accessToken, String refreshToken, String discoveryUrl) {

    Map<String, Object> sourceInfoMap = new HashMap<>();
    sourceInfoMap.put(ACCESS_TOKEN, accessToken);
    sourceInfoMap.put(REFRESH_TOKEN, refreshToken);
    sourceInfoMap.put(DISCOVERY_URL, discoveryUrl);

    return GSON.toJson(Collections.singletonMap(sourceId, sourceInfoMap));
  }

  /**
   * @return a Json representation of the data after removing tokens associated to the given source
   */
  static String removeTokens(TokenInformation existingTokenInformation, String sourceId) {
    Map<String, Object> jsonMap =
        GSON.fromJson(existingTokenInformation.getTokenJson(), MAP_STRING_TO_OBJECT_TYPE);
    jsonMap.remove(sourceId);
    return GSON.toJson(jsonMap);
  }

  @Override
  public String getId() {
    return id;
  }

  @Override
  public String getUserId() {
    return userId;
  }

  @Override
  public Map<String, TokenEntry> getTokenEntries() {
    return tokenEntryList;
  }

  @Override
  public Set<String> getDiscoveryUrls() {
    return discoveryUrls;
  }

  @Override
  public String getTokenJson() {
    return json;
  }

  public static class TokenEntryImpl implements TokenEntry {

    private String accessToken;
    private String refreshToken;
    private String discoveryUrl;

    public TokenEntryImpl(String accessToken, String refreshToken, String discoveryUrl) {
      this.accessToken = accessToken;
      this.refreshToken = refreshToken;
      this.discoveryUrl = discoveryUrl;
    }

    @Override
    public String getAccessToken() {
      return accessToken;
    }

    @Override
    public String getRefreshToken() {
      return refreshToken;
    }

    @Override
    public String getDiscoveryUrl() {
      return discoveryUrl;
    }
  }
}
