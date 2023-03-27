package org.springframework.security.oauth2.server.authorization.utils;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

/**
 * @see OAuth2Authorization
 */
public abstract class OAuth2AuthorizationMixin {

//	@JsonCreator
//	public OAuth2AuthorizationMixin() {
//	}

    @JsonIgnore
    public abstract void setAccessToken(OAuth2AccessToken token);

//    @JsonProperty("access_token")
//    public abstract void setAccessToken(OAuth2AccessToken token);

}
