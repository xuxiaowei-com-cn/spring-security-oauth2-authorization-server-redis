package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.annotation.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;

import java.util.Set;

/**
 * {@link OAuth2AuthorizationConsent} 反序列化
 * <p>
 * <code>org.springframework.security.web.jackson2.WebAuthenticationDetailsMixin</code>
 *
 * @since 0.0.1
 * @author xuxiaowei
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
		isGetterVisibility = JsonAutoDetect.Visibility.NONE, creatorVisibility = JsonAutoDetect.Visibility.ANY)
public class OAuth2AuthorizationConsentMixin {

	@JsonCreator
	OAuth2AuthorizationConsentMixin(@JsonProperty("registeredClientId") String registeredClientId,
			@JsonProperty("principalName") String principalName,
			@JsonProperty("authorities") Set<GrantedAuthority> authorities) {
	}

}
