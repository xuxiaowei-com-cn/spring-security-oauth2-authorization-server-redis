package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

public class OAuth2AuthorizationCodeGeneratorUtils {

	public static OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
		return new OAuth2AuthorizationCodeGenerator().generate(context);
	}

}
