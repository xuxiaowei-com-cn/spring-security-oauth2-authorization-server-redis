package org.springframework.security.oauth2.server.authorization.deserializer;

/*-
 * #%L
 * spring-security-oauth2-authorization-server-redis
 * %%
 * Copyright (C) 2022 - 2023 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.core.type.TypeReference;
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

	private final ObjectMapper objectMapper = new ObjectMapper();

	public OAuth2AuthorizationConsentDeserializer() {
		super(OAuth2AuthorizationConsent.class);
	}

	@Override
	@SuppressWarnings("unchecked")
	public OAuth2AuthorizationConsent deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JacksonException {
		TreeNode treeNode = p.getCodec().readTree(p);

		String treeNodeStr = treeNode.toString();
		Map<String, Object> treeNodeMap = objectMapper.readValue(treeNodeStr, new TypeReference<Map<String, Object>>() {
		});

		String registeredClientId = treeNodeMap.get("registeredClientId").toString();
		String principalName = treeNodeMap.get("principalName").toString();

		Set<GrantedAuthority> authorities = new HashSet<>();
		toSetAuthorities(treeNodeMap.get("authorities"), authorities);

		OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent
			.withId(registeredClientId, principalName)
			.authorities(authorities::addAll);

		Object scopesObj = treeNodeMap.get("scopes");
		if (scopesObj instanceof List) {
			List<Object> list = (List<Object>) scopesObj;
			list.stream()
				.filter(o -> o instanceof Map)
				.map(map -> (Map<String, String>) map)
				.flatMap(map -> map.values().stream())
				.forEach(builder::scope);
		}

		return builder.build();
	}

	@SuppressWarnings("unchecked")
	private void toSetAuthorities(Object authoritiesObj, Set<GrantedAuthority> authorities) {
		if (authoritiesObj instanceof List) {
			List<Object> list = (List<Object>) authoritiesObj;
			list.stream()
				.filter(o -> o instanceof Map)
				.map(map -> (Map<String, String>) map)
				.flatMap(map -> map.values().stream())
				.map(SimpleGrantedAuthority::new)
				.forEach(authorities::add);
		}
	}

}
