package org.springframework.security.oauth2.server.authorization.utils;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;

public class OAuth2AuthorizationJackson2Module extends SimpleModule {

	public OAuth2AuthorizationJackson2Module() {
		super(OAuth2AuthorizationJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
//		context.setMixInAnnotations(OAuth2Authorization.class, OAuth2AuthorizationMixin.class);
		context.setMixInAnnotations(AuthorizationGrantType.class, AuthorizationGrantTypeMixin.class);
	}

}
