package org.springframework.security.oauth2.server.authorization.deserializer;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.io.IOException;

/**
 * {@link OAuth2Authorization} 反序列化
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class OAuth2AuthorizationDeserializer extends StdDeserializer<OAuth2Authorization> {

	public OAuth2AuthorizationDeserializer() {
		this(null);
	}

	public OAuth2AuthorizationDeserializer(Class<?> vc) {
		super(vc);
	}

	@Override
	public OAuth2Authorization deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JacksonException {
		TreeNode treeNode = p.getCodec().readTree(p);

		RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(treeNode.get("id").toString());

		RegisteredClient registeredClient = registeredClientBuilder.build();

		// @formatter:off
		OAuth2Authorization.Builder oauth2AuthorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient);
		// @formatter:on

		return oauth2AuthorizationBuilder.build();
	}

}
