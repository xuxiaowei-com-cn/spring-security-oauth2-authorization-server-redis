package org.springframework.security.oauth2.server.authorization.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames.Client.TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM;
import static org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames.Token.*;

/**
 * {@link RegisteredClient} 序列化与反序列化
 *
 * @see RegisteredClient
 * @author xuxiaowei
 */
@Slf4j
class RegisteredClientTests {

	/**
	 * ID
	 */
	public static final String ID = "bcc73542-6c8e-44e7-a1b4-51f1c4089268";

	/**
	 * 客户ID
	 */
	public static final String CLIENT_ID = "xuxiaowei_client_id";

	/**
	 * @see JdbcRegisteredClientRepository#save(RegisteredClient)
	 * @see JdbcRegisteredClientRepository.RegisteredClientRowMapper
	 * @see JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper
	 * @see JdbcRegisteredClientRepository.RegisteredClientRowMapper#mapRow(ResultSet,
	 * int)
	 * @see JdbcRegisteredClientRepository.RegisteredClientRowMapper#parseMap(String)
	 */
	@Test
	void builder() throws JsonProcessingException {

		RegisteredClient.Builder builder = RegisteredClient.withId(ID)
			.clientId(CLIENT_ID)
			.clientIdIssuedAt(Instant.now())
			.clientSecret(UUID.randomUUID().toString())
			.clientSecretExpiresAt(Instant.now().plus(100, ChronoUnit.DAYS))
			.clientName(UUID.randomUUID().toString())
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
			// .clientAuthenticationMethods()
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			// .authorizationGrantTypes()
			.redirectUri("http://127.0.0.1:1401/code")
			// .redirectUris()
			.scope("snsapi_base")
			// .scopes()
			.clientSettings(clientSettings())
			.tokenSettings(tokenSettings());

		RegisteredClient registeredClient = builder.build();

		ClassLoader classLoader = JdbcRegisteredClientRepository.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.registerModules(securityModules);
		objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

		ObjectWriter objectWriter = objectMapper.writerWithDefaultPrettyPrinter();

		String writeValueAsString = objectWriter.writeValueAsString(registeredClient);
		log.info("\n{}", writeValueAsString);

		RegisteredClient client = stringToRegisteredClient(writeValueAsString);
		String s = objectWriter.writeValueAsString(client);
		log.info("\n{}", s);

	}

	private RegisteredClient stringToRegisteredClient(String string) throws JsonProcessingException {
		ObjectMapper objectMapper = new ObjectMapper();

		// 使用新 ObjectMapper
		Map<String, Object> readValue = objectMapper.readValue(string, new TypeReference<Map<String, Object>>() {
		});

		Instant clientIdIssuedAt = toInstant(readValue.get("clientIdIssuedAt"));
		Instant clientSecretExpiresAt = toInstant(readValue.get("clientSecretExpiresAt"));

		Set<String> clientAuthenticationMethods = toSet(readValue.get("clientAuthenticationMethods"));
		Set<String> authorizationGrantTypes = toSet(readValue.get("authorizationGrantTypes"));
		Set<String> redirectUris = toSet(readValue.get("redirectUris"));
		Set<String> clientScopes = toSet(readValue.get("scopes"));

		RegisteredClient.Builder builder = RegisteredClient.withId(toString(readValue.get("id")))
			.clientId(toString(readValue.get("clientId")))
			.clientIdIssuedAt(clientIdIssuedAt)
			.clientSecret(toString(readValue.get("clientSecret")))
			.clientSecretExpiresAt(clientSecretExpiresAt)
			.clientName(toString(readValue.get("clientName")))
			.clientAuthenticationMethods((authenticationMethods) -> clientAuthenticationMethods
				.forEach(authenticationMethod -> authenticationMethods
					.add(resolveClientAuthenticationMethod(authenticationMethod))))
			.authorizationGrantTypes((grantTypes) -> authorizationGrantTypes
				.forEach(grantType -> grantTypes.add(resolveAuthorizationGrantType(grantType))))
			.redirectUris((uris) -> uris.addAll(redirectUris))
			.scopes((scopes) -> scopes.addAll(clientScopes));

		Map<String, Object> clientSettingsMap = parseMap(readValue.get("clientSettings"));
		builder.clientSettings(ClientSettings.withSettings(toSettingsMap(clientSettingsMap)).build());

		Map<String, Object> tokenSettingsMap = parseMap(readValue.get("tokenSettings"));
		TokenSettings.Builder tokenSettingsBuilder = TokenSettings.withSettings(toSettingsMap(tokenSettingsMap));

		if (!tokenSettingsMap.containsKey(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT)) {
			tokenSettingsBuilder.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED);
		}
		builder.tokenSettings(tokenSettingsBuilder.build());

		return builder.build();
	}

	private Map<String, Object> toSettingsMap(Map<String, Object> clientSettingsMap) throws JsonProcessingException {
		Object settingsObj = clientSettingsMap.get("settings");
		if (settingsObj instanceof Map) {
			@SuppressWarnings("unchecked")
			Map<String, Object> map = (Map<String, Object>) settingsObj;
			map.remove("@class");

			Object tokenEndpointAuthenticationSigningAlgorithm = map
				.get(TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM);
			if (tokenEndpointAuthenticationSigningAlgorithm != null) {
				if (tokenEndpointAuthenticationSigningAlgorithm instanceof List) {

					@SuppressWarnings("unchecked")
					List<String> values = (List<String>) tokenEndpointAuthenticationSigningAlgorithm;

					String c = values.get(0);
					String v = values.get(1);
					if (SignatureAlgorithm.class.getName().equals(c)) {
						map.put(TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM, SignatureAlgorithm.from(v));
					}
					else if (MacAlgorithm.class.getName().equals(c)) {
						map.put(TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM, MacAlgorithm.from(v));
					}
				}
			}

			Object idTokenSignatureAlgorithm = map.get(ID_TOKEN_SIGNATURE_ALGORITHM);
			if (idTokenSignatureAlgorithm != null) {
				if (idTokenSignatureAlgorithm instanceof List) {

					@SuppressWarnings("unchecked")
					List<String> values = (List<String>) idTokenSignatureAlgorithm;

					String c = values.get(0);
					String v = values.get(1);
					if (SignatureAlgorithm.class.getName().equals(c)) {
						map.put(ID_TOKEN_SIGNATURE_ALGORITHM, SignatureAlgorithm.from(v));
					}
					else if (MacAlgorithm.class.getName().equals(c)) {
						map.put(ID_TOKEN_SIGNATURE_ALGORITHM, MacAlgorithm.from(v));
					}
				}
			}

			Object authorizationCodeTimeToLive = map.get(AUTHORIZATION_CODE_TIME_TO_LIVE);
			if (authorizationCodeTimeToLive != null) {
				if (authorizationCodeTimeToLive instanceof List) {

					@SuppressWarnings("unchecked")
					List<Object> values = (List<Object>) authorizationCodeTimeToLive;

					Duration duration = Duration.ofSeconds(((Double) values.get(1)).longValue());
					map.put(AUTHORIZATION_CODE_TIME_TO_LIVE, duration);
				}
			}

			Object accessTokenTimeToLive = map.get(ACCESS_TOKEN_TIME_TO_LIVE);
			if (accessTokenTimeToLive != null) {
				if (accessTokenTimeToLive instanceof List) {

					@SuppressWarnings("unchecked")
					List<Object> values = (List<Object>) accessTokenTimeToLive;

					Duration duration = Duration.ofSeconds(((Double) values.get(1)).longValue());
					map.put(ACCESS_TOKEN_TIME_TO_LIVE, duration);

				}
			}

			Object refreshTokenTimeToLive = map.get(REFRESH_TOKEN_TIME_TO_LIVE);
			if (refreshTokenTimeToLive != null) {
				if (refreshTokenTimeToLive instanceof List) {

					@SuppressWarnings("unchecked")
					List<Object> values = (List<Object>) refreshTokenTimeToLive;

					Duration duration = Duration.ofSeconds(((Double) values.get(1)).longValue());
					map.put(REFRESH_TOKEN_TIME_TO_LIVE, duration);

				}
			}

			return map;
		}
		return clientSettingsMap;
	}

	private Instant toInstant(Object object) {
		if (object instanceof Double) {
			Double d = (Double) object;
			// return Instant.ofEpochMilli(d.longValue());
			return Instant.ofEpochSecond(d.longValue(), (int) ((d % 1) * 1_000_000_000));
		}
		return null;
	}

	private String toString(Object object) {
		if (object instanceof String) {
			return (String) object;
		}
		return null;
	}

	private Set<String> toSet(Object object) {
		if (object instanceof List) {
			@SuppressWarnings("unchecked")
			List<Object> iList = (List<Object>) object;
			HashSet<String> set = new HashSet<>();
			for (Object iObject : iList) {
				if (iObject instanceof List) {
					@SuppressWarnings("unchecked")
					List<Object> jList = (List<Object>) iObject;
					for (Object jObject : jList) {
						if (jObject instanceof Map) {
							@SuppressWarnings("unchecked")
							Map<String, String> map = (Map<String, String>) jObject;
							set.addAll(map.values());
						}
						else if (jObject instanceof String) {
							set.add((String) jObject);
						}
					}
				}
			}
			return set;
		}
		String string = toString(object);
		return StringUtils.commaDelimitedListToSet(string);
	}

	private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
		if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		}
		else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_POST;
		}
		else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.NONE;
		}
		return new ClientAuthenticationMethod(clientAuthenticationMethod);
	}

	private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.AUTHORIZATION_CODE;
		}
		else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.CLIENT_CREDENTIALS;
		}
		else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.REFRESH_TOKEN;
		}
		return new AuthorizationGrantType(authorizationGrantType);
	}

	private Map<String, Object> parseMap(Object data) {
		if (data instanceof Map) {
			@SuppressWarnings("unchecked")
			Map<String, Object> map = (Map<String, Object>) data;
			return map;
		}

		try {
			return new ObjectMapper().readValue((String) data, new TypeReference<Map<String, Object>>() {
			});
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	private ClientSettings clientSettings() {
		ClientSettings.Builder builder = ClientSettings.builder()
			.requireProofKey(true)
			.requireAuthorizationConsent(false)
			.jwkSetUrl("http://127.0.0.1:1401/jwk")
			.tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.RS256);

		return builder.build();
	}

	private TokenSettings tokenSettings() {
		TokenSettings.Builder builder = TokenSettings.builder()
			.authorizationCodeTimeToLive(Duration.ofMinutes(5))
			.accessTokenTimeToLive(Duration.ofDays(1))
			.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
			.reuseRefreshTokens(true)
			.refreshTokenTimeToLive(Duration.ofDays(20))
			.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256);

		return builder.build();
	}

}
