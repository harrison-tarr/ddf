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

import ddf.security.Subject;
import org.apache.cxf.jaxrs.client.Client;

public interface OAuthSecurity {

  String OAUTH = "OAUTH";

  /**
   * Retrieves the system's access token from the configured OAuth provider and sets it to the OAUTH
   * header
   *
   * @param client Non-null client to set the access token on.
   * @param clientId The client ID registered with the OAuth provider
   * @param clientSecret The client secret registered with the OAuth provider
   * @param discoveryUrl the metadata URL of the OAuth provider
   */
  void setSystemTokenOnClient(
      Client client, String clientId, String clientSecret, String discoveryUrl);

  /**
   * Gets the user's access token from the token storage to set it to the OAUTH header.
   *
   * @param client Non-null client to set the access token on.
   * @param subject subject used to get the user's id (email or username)
   * @param sourceId the id of the source using OAuth needed to get the correct tokens
   */
  void setUserTokenOnClient(Client client, Subject subject, String sourceId);
}