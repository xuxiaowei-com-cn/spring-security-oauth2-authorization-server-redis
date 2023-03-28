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
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.io.IOException;
import java.security.Principal;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
		ObjectMapper objectMapper = new ObjectMapper();

		TreeNode treeNode = p.getCodec().readTree(p);

		String treeNodeStr = treeNode.toString();
		@SuppressWarnings("all")
		Map<String, Object> treeNodeMap = objectMapper.readValue(treeNodeStr, Map.class);

		RegisteredClient.Builder registeredClientBuilder = RegisteredClient
			.withId(treeNodeMap.get("registeredClientId").toString());
		String authorizationGrantTypeStr = treeNode.get("authorizationGrantType").toString();
		String principalName = treeNodeMap.get("principalName").toString();

		@SuppressWarnings("all")
		Map<String, String> authorizationGrantTypeMap = objectMapper.readValue(authorizationGrantTypeStr, Map.class);

		registeredClientBuilder.authorizationGrantTypes(authorizationGrantTypes -> {
			for (String value : authorizationGrantTypeMap.values()) {
				authorizationGrantTypes.add(new AuthorizationGrantType(value));
			}
		});

		TreeNode attributes = treeNode.get("attributes");

		Object principalObj = attributes.get(Principal.class.getName());

		String oauth2AuthorizationRequestStr = attributes.get(OAuth2AuthorizationRequest.class.getName()).toString();

		@SuppressWarnings("all")
		Map<String, Object> oauth2AuthorizationRequestMap = objectMapper.readValue(oauth2AuthorizationRequestStr,
				Map.class);

		String clientId = oauth2AuthorizationRequestMap.get("clientId").toString();
		registeredClientBuilder.clientId(clientId);

		AuthorizationGrantType authorizationGrantType = null;
		for (String value : authorizationGrantTypeMap.values()) {
			authorizationGrantType = new AuthorizationGrantType(value);
		}

		OAuth2AuthorizationRequest oauth2AuthorizationRequest = null;
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {

			Object scopesObj = oauth2AuthorizationRequestMap.get("scopes");
			Set<String> scopes = new HashSet<>();
			if (scopesObj instanceof List) {
				@SuppressWarnings("all")
				List<String> scopesList = (List) scopesObj;
				scopes.addAll(scopesList);
			}

			OAuth2AuthorizationRequest.Builder oauth2AuthorizationRequestBuilder = OAuth2AuthorizationRequest
				.authorizationCode()
				.authorizationUri(oauth2AuthorizationRequestMap.get("authorizationUri").toString())
				.clientId(clientId)
				.redirectUri(oauth2AuthorizationRequestMap.get("redirectUri").toString())
				.scopes(scopes)
				.state(oauth2AuthorizationRequestMap.get("state").toString());

			oauth2AuthorizationRequest = oauth2AuthorizationRequestBuilder.build();
		}

		String redirectUri = oauth2AuthorizationRequestMap.get("redirectUri").toString();

		registeredClientBuilder.redirectUri(redirectUri);

		RegisteredClient registeredClient = registeredClientBuilder.build();

		OAuth2AccessToken accessToken = null;
		Object accessTokenObj = treeNodeMap.get("accessToken");
		if (accessTokenObj instanceof Map) {
			@SuppressWarnings("all")
			Map<String, Object> accessTokenMap = (Map) accessTokenObj;
			Object tokenObj = accessTokenMap.get("token");
			if (tokenObj instanceof Map) {
				@SuppressWarnings("all")
				Map<String, Object> tokenMap = (Map) tokenObj;
				String tokenValue = tokenMap.get("tokenValue").toString();
				Object tokenTypeObj = tokenMap.get("tokenType");

				OAuth2AccessToken.TokenType tokenType = null;
				if (tokenTypeObj instanceof Map) {
					@SuppressWarnings("all")
					Map<String, String> tokenTypeMap = (Map) tokenTypeObj;
					String value = tokenTypeMap.get("value");
					if (OAuth2AccessToken.TokenType.BEARER.getValue().equals(value)) {
						tokenType = OAuth2AccessToken.TokenType.BEARER;
					}
				}

				String issuedAtStr = tokenMap.get("issuedAt").toString();
				String expiresAtStr = tokenMap.get("expiresAt").toString();
				Object scopesObj = tokenMap.get("scopes");

				Set<String> scopes = new HashSet<>();
				if (scopesObj instanceof List) {
					@SuppressWarnings("all")
					List<String> scopesList = (List) scopesObj;
					scopes.addAll(scopesList);
				}

				Instant issuedAt = Instant.parse(issuedAtStr);
				Instant expiresAt = Instant.parse(expiresAtStr);

				assert tokenType != null;
				accessToken = new OAuth2AccessToken(tokenType, tokenValue, issuedAt, expiresAt, scopes);
			}
		}

		OAuth2RefreshToken refreshToken = null;
		Object refreshTokenObj = treeNodeMap.get("refreshToken");
		if (refreshTokenObj instanceof Map) {
			@SuppressWarnings("all")
			Map<String, Object> refreshTokenMap = (Map) refreshTokenObj;
			Object tokenObj = refreshTokenMap.get("token");
			if (tokenObj instanceof Map) {
				@SuppressWarnings("all")
				Map<String, String> tokenMap = (Map) tokenObj;
				String tokenValue = tokenMap.get("tokenValue");
				String issuedAtStr = tokenMap.get("issuedAt");
				String expiresAtStr = tokenMap.get("expiresAt");

				Instant issuedAt = Instant.parse(issuedAtStr);

				Instant expiresAt;
				if (expiresAtStr == null) {
					expiresAt = null;
				}
				else {
					expiresAt = Instant.parse(expiresAtStr);
				}

				refreshToken = new OAuth2RefreshToken(tokenValue, issuedAt, expiresAt);
			}
		}

		String id = treeNodeMap.get("id").toString();

		OAuth2Authorization.Builder oauth2AuthorizationBuilder = OAuth2Authorization
			.withRegisteredClient(registeredClient)
			.id(id)
			.accessToken(accessToken)
			.refreshToken(refreshToken)
			.principalName(principalName)
			.authorizationGrantType(authorizationGrantType)
			.attribute(OAuth2AuthorizationRequest.class.getName(), oauth2AuthorizationRequest);

		return oauth2AuthorizationBuilder.build();
	}

}
