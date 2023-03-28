package org.springframework.security.oauth2.server.authorization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.sql.ResultSet;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * {@link OAuth2Authorization} 序列化与反序列化
 *
 * @see OAuth2Authorization
 * @author xuxiaowei
 */
@Slf4j
class OAuth2AuthorizationTests {

	/**
	 * ID
	 */
	public static final String ID = "bcc73542-6c8e-44e7-a1b4-51f1c4089268";

	/**
	 * 客户ID
	 */
	public static final String CLIENT_ID = "xuxiaowei_client_id";

	/**
	 * 权限ID
	 */
	public static final String AUTHORIZATION_ID = "c703d612-e89b-48a9-b951-b24251fa58c2";

	/**
	 *
	 */
	public static final String ACCESS_TOKEN_VALUE = "d8e3e7c0-3ca0-4797-a30b-51385a47f921";

	/**
	 *
	 */
	public static final String REFRESH_TOKEN_VALUE = "d8e3e7c0-3ca0-4797-a30b-51385a47f921";

	/**
	 *
	 */
	public static final String STATE = "ad33a641-a8c6-4c3b-9e97-379694dfd9da";

	/**
	 * @see JdbcOAuth2AuthorizationService#save(OAuth2Authorization)
	 * @see JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper
	 * @see JdbcOAuth2AuthorizationService#findById(String)
	 * @see JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper#mapRow(ResultSet,
	 * int)
	 */
	@Test
	void builder() throws JsonProcessingException {

		Instant issuedAt = Instant.now();
		Instant expiresAt = Instant.now().plus(1, ChronoUnit.DAYS);

		// @formatter:off
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_TOKEN_VALUE, issuedAt, expiresAt);
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(REFRESH_TOKEN_VALUE, Instant.now().plus(2, ChronoUnit.DAYS));
		// @formatter:on

		RegisteredClient registeredClient = registeredClient();

		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient)
			.id(AUTHORIZATION_ID)
			.principalName("zhang-san")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizedScopes(Collections.singleton("snsapi_base"))
			.accessToken(accessToken)
			.refreshToken(refreshToken)
			// .token()
			// .token()
			// .tokens()
			.attribute(Principal.class.getName(), principal())
			.attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest(registeredClient))
		// .attributes()
		;

		OAuth2Authorization auth2Authorization = builder.build();

		ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		ObjectMapper objectMapper = new ObjectMapper();
		objectMapper.registerModules(securityModules);
		objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

		ObjectWriter objectWriter = objectMapper.writerWithDefaultPrettyPrinter();

		String writeValueAsString = objectWriter.writeValueAsString(auth2Authorization);
		log.info("\n{}", writeValueAsString);

		OAuth2Authorization authorization = stringToOAuth2Authorization(writeValueAsString);
		String s = objectWriter.writeValueAsString(authorization);
		log.info("\n{}", s);

	}

	private OAuth2Authorization stringToOAuth2Authorization(String string) throws JsonProcessingException {

		ObjectMapper objectMapper = new ObjectMapper();

		// 使用新 ObjectMapper
		Map<String, Object> readValue = objectMapper.readValue(string, new TypeReference<Map<String, Object>>() {
		});

		String registeredClientId = toString(readValue.get("registeredClientId"));

		// @formatter:off
//		RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientId);
//		if (registeredClient == null) {
//			throw new DataRetrievalFailureException(
//					"The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
//		}
		// @formatter:on

		OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient());
		String id = toString(readValue.get("id"));
		String principalName = toString(readValue.get("principalName"));
		AuthorizationGrantType authorizationGrantType = toAuthorizationGrantType(
				readValue.get("authorizationGrantType"));
		Set<String> authorizedScopes = Collections.emptySet();
		String authorizedScopesString = toString(readValue.get("authorizedScopes"));
		if (authorizedScopesString != null) {
			authorizedScopes = StringUtils.commaDelimitedListToSet(authorizedScopesString);
		}

		Map<String, Object> attributes = parseMap(readValue.get("attributes"));

		// Map<String, Object> attributes = parseMap(getLobValue(rs, "attributes"));

		builder.id(id)
			.principalName(principalName)
			.authorizationGrantType(authorizationGrantType)
			.authorizedScopes(authorizedScopes)
			.attributes((attrs) -> attrs.putAll(attributes));

		String state = toString(readValue.get("state"));
		if (StringUtils.hasText(state)) {
			builder.attribute(OAuth2ParameterNames.STATE, state);
		}

		Instant tokenIssuedAt;
		Instant tokenExpiresAt;
		String authorizationCodeValue = toString(readValue.get("authorizationCodeValue"));

		if (StringUtils.hasText(authorizationCodeValue)) {
			tokenIssuedAt = toInstant(readValue.get("authorizationCodeIssuedAt"));
			tokenExpiresAt = toInstant(readValue.get("authorizationCodeExpiresAt"));

			Map<String, Object> authorizationCodeMetadata = parseMap(readValue.get("authorizationCodeMetadata"));

			OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(authorizationCodeValue,
					tokenIssuedAt, tokenExpiresAt);
			builder.token(authorizationCode, (metadata) -> metadata.putAll(authorizationCodeMetadata));
		}

		String accessTokenValue = toString(readValue.get("accessTokenValue"));
		if (StringUtils.hasText(accessTokenValue)) {

			tokenIssuedAt = toInstant(readValue.get("accessTokenIssuedAt"));
			tokenExpiresAt = toInstant(readValue.get("accessTokenExpiresAt"));

			Map<String, Object> accessTokenMetadata = parseMap(readValue.get("accessTokenMetadata"));
			OAuth2AccessToken.TokenType tokenType = null;
			if (OAuth2AccessToken.TokenType.BEARER.getValue()
				.equalsIgnoreCase(toString(readValue.get("accessTokenType")))) {
				tokenType = OAuth2AccessToken.TokenType.BEARER;
			}

			Set<String> scopes = Collections.emptySet();
			String accessTokenScopes = toString(readValue.get("accessTokenScopes"));
			if (accessTokenScopes != null) {
				scopes = StringUtils.commaDelimitedListToSet(accessTokenScopes);
			}
			OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, accessTokenValue, tokenIssuedAt,
					tokenExpiresAt, scopes);
			builder.token(accessToken, (metadata) -> metadata.putAll(accessTokenMetadata));
		}

		String oidcIdTokenValue = toString(readValue.get("oidcIdTokenValue"));
		if (StringUtils.hasText(oidcIdTokenValue)) {

			tokenIssuedAt = toInstant(readValue.get("oidcIdTokenIssuedAt"));
			tokenExpiresAt = toInstant(readValue.get("oidcIdTokenExpiresAt"));

			Map<String, Object> oidcTokenMetadata = parseMap(readValue.get("oidcIdTokenMetadata"));
			@SuppressWarnings("unchecked")
			Map<String, Object> claims = (Map<String, Object>) oidcTokenMetadata
				.get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME);
			OidcIdToken oidcToken = new OidcIdToken(oidcIdTokenValue, tokenIssuedAt, tokenExpiresAt, claims);
			builder.token(oidcToken, (metadata) -> metadata.putAll(oidcTokenMetadata));
		}

		String refreshTokenValue = toString(readValue.get("refreshTokenValue"));
		if (StringUtils.hasText(refreshTokenValue)) {
			tokenIssuedAt = toInstant(readValue.get("refreshTokenIssuedAt"));
			tokenExpiresAt = toInstant(readValue.get("refreshTokenExpiresAt"));
			Map<String, Object> refreshTokenMetadata = parseMap(readValue.get("refreshTokenMetadata"));

			OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refreshTokenValue, tokenIssuedAt, tokenExpiresAt);
			builder.token(refreshToken, (metadata) -> metadata.putAll(refreshTokenMetadata));
		}
		return builder.build();
	}

	private RegisteredClient registeredClient() {
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

		return builder.build();
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

	private Authentication principal() {
		List<GrantedAuthority> authorities = new ArrayList<>();
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority("student");
		authorities.add(authority);
		User user = new User("zhang-san", "", authorities);
		return new UsernamePasswordAuthenticationToken(user, null);
	}

	private OAuth2AuthorizationRequest authorizationRequest(RegisteredClient registeredClient) {
		return OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri("http://192.168.1.101:1401/oauth2/authorize")
			.clientId(registeredClient.getClientId())
			.redirectUri("http://127.0.0.1:1401/code")
			.scopes(Collections.singleton("snsapi_base"))
			.state(STATE)
			.additionalParameters(new HashMap<>())
			.build();
	}

	private AuthorizationGrantType toAuthorizationGrantType(Object object) throws JsonProcessingException {
		if (object instanceof Map) {
			@SuppressWarnings("unchecked")
			Map<String, String> map = (Map<String, String>) object;
			return new AuthorizationGrantType(map.get("value"));
		}
		return null;
	}

	private String toString(Object object) {
		if (object instanceof String) {
			return (String) object;
		}
		return null;
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

	private Instant toInstant(Object object) {
		if (object instanceof Double) {
			Double d = (Double) object;
			// return Instant.ofEpochMilli(d.longValue());
			return Instant.ofEpochSecond(d.longValue(), (int) ((d % 1) * 1_000_000_000));
		}
		return null;
	}

}
