package org.springframework.security.oauth2.server.authorization.jackson2;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;

/**
 * 反序列化
 *
 * @see org.springframework.security.web.jackson2.WebServletJackson2Module
 * @since 0.0.1
 * @author xuxiaowei
 */
public class OAuth2AuthorizationJackson2Module extends SimpleModule {

	public OAuth2AuthorizationJackson2Module() {
		super(OAuth2AuthorizationJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
	}

	@Override
	public void setupModule(SetupContext context) {
		SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
		context.setMixInAnnotations(OAuth2AuthorizationConsent.class, OAuth2AuthorizationConsentMixin.class);
	}

}
