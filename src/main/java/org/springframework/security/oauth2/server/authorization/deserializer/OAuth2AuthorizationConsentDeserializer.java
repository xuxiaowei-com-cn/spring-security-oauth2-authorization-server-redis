package org.springframework.security.oauth2.server.authorization.deserializer;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class OAuth2AuthorizationConsentDeserializer extends StdDeserializer<OAuth2AuthorizationConsent> {

	public OAuth2AuthorizationConsentDeserializer() {
		this(null);
	}

	public OAuth2AuthorizationConsentDeserializer(Class<?> vc) {
		super(vc);
	}

	@Override
	public OAuth2AuthorizationConsent deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JacksonException {
		ObjectMapper objectMapper = new ObjectMapper();

		TreeNode treeNode = p.getCodec().readTree(p);

		String treeNodeStr = treeNode.toString();
		@SuppressWarnings("all")
		Map<String, Object> treeNodeMap = objectMapper.readValue(treeNodeStr, Map.class);

		String registeredClientId = treeNodeMap.get("registeredClientId").toString();
		String principalName = treeNodeMap.get("principalName").toString();

		Object authoritiesObj = treeNodeMap.get("authorities");
		Set<GrantedAuthority> authorities = new HashSet<>();
		toSetAuthorities(authoritiesObj, authorities);

		Object scopesObj = treeNodeMap.get("scopes");

		OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent
			.withId(registeredClientId, principalName)
			.authorities(authoritySet -> {
				authoritySet.addAll(authorities);
			});

		if (scopesObj instanceof List) {
			@SuppressWarnings("all")
			List<Object> list = (List<Object>) scopesObj;
			for (Object o : list) {
				if (o instanceof Map) {
					@SuppressWarnings("all")
					Map<String, String> map = (Map<String, String>) o;
					for (String s : map.values()) {
						builder.scope(s);
					}
				}
			}
		}

		return builder.build();
	}

	private void toSetAuthorities(Object authoritiesObj, Set<GrantedAuthority> authorities) {
		if (authoritiesObj instanceof List) {
			@SuppressWarnings("all")
			List<Object> list = (List<Object>) authoritiesObj;
			for (Object o : list) {
				if (o instanceof Map) {
					@SuppressWarnings("all")
					Map<String, String> map = (Map<String, String>) o;
					for (String s : map.values()) {
						authorities.add(new SimpleGrantedAuthority(s));
					}
				}
			}
		}
	}

}
