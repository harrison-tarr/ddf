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
package ddf.catalog.source;

public interface OAuthFederatedSource extends FederatedSource {

  /** @return true if the source is configured to use OAuth and false otherwise. */
  boolean isUseOauth();

  /** @return the configured OAuth provider's url */
  String getOauthDiscoveryUrl();

  /** @return client id registered with the OAuth provider */
  String getOauthClientId();

  /** @return client secret registered with the OAuth provider */
  String getOauthClientSecret();

  /** @return the configured flow to use for OAuth federation */
  String getOauthFlow();
}
