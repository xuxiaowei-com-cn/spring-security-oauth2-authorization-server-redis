package cn.com.xuxiaowei.boot.oauth2.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.TreeNode;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.security.Principal;
import java.time.Instant;
import java.util.*;

/**
 * {@link OAuth2Authorization} 反序列化
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Slf4j
public class OAuth2AuthorizationDeserializer extends StdDeserializer<OAuth2Authorization> {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public OAuth2AuthorizationDeserializer() {
		super(OAuth2Authorization.class);
	}

	@Override
	public OAuth2Authorization deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {

		SimpleModule module = new SimpleModule();
		module.addDeserializer(BigDecimal.class, new BigDecimalDeserializer());
		OBJECT_MAPPER.registerModule(module);

		RegisteredClient.Builder registeredClientBuilder = null;
		AuthorizationGrantType authorizationGrantType = null;
		String principalName = null;
		OAuth2AccessToken accessToken = null;
		OAuth2RefreshToken refreshToken = null;
		Map<String, Object> attributesMap = null;
		String id = null;
		Set<String> authorizedScopes = null;

		JsonToken token;
		while ((token = p.nextToken()) != null) {
			if (JsonToken.FIELD_NAME.equals(token)) {
				String fieldName = p.getCurrentName();
				// 下一个值
				p.nextToken();
				switch (fieldName) {
					case "id":
						id = p.getText();
						break;
					case "registeredClientId":
						registeredClientBuilder = RegisteredClient.withId(p.getText());
						break;
					case "principalName":
						principalName = p.getText();
						break;
					case "authorizationGrantType":
						authorizationGrantType = OBJECT_MAPPER.convertValue(
								p.readValueAs(Map.class).values().iterator().next(), AuthorizationGrantType.class);
						break;
					case "authorizedScopes":
						authorizedScopes = p.readValueAs(new TypeReference<Set<String>>() {
						});
						break;
					case "attributes":
						attributesMap = OBJECT_MAPPER.convertValue(p.readValueAsTree(),
								new TypeReference<Map<String, Object>>() {
								});
						break;
					case "accessToken":
						accessToken = accessToken(p);
						break;
					case "refreshToken":
						refreshToken = refreshToken(p);
						break;

					default:

				}
			}
		}

		Object oauth2AuthorizationRequestObject = attributesMap.get(OAuth2AuthorizationRequest.class.getName());
		attributesMap.remove(OAuth2AuthorizationRequest.class.getName());

		Map<String, Object> oauth2AuthorizationRequestMap = OBJECT_MAPPER.convertValue(oauth2AuthorizationRequestObject,
				new TypeReference<Map<String, Object>>() {
				});

		String clientId = oauth2AuthorizationRequestMap.get("clientId").toString();
		registeredClientBuilder.clientId(clientId);

		String redirectUri = oauth2AuthorizationRequestMap.get("redirectUri").toString();
		registeredClientBuilder.redirectUri(redirectUri);

		Object state = oauth2AuthorizationRequestMap.get(OAuth2ParameterNames.STATE);
		Object scopes = oauth2AuthorizationRequestMap.get("scopes");

		OAuth2AuthorizationRequest oauth2AuthorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationRequestUri(oauth2AuthorizationRequestMap.get("authorizationRequestUri").toString())
			.authorizationUri(oauth2AuthorizationRequestMap.get("authorizationUri").toString())
			.redirectUri(oauth2AuthorizationRequestMap.get("redirectUri").toString())
			.clientId(clientId)
			.state(state == null ? null : state.toString())
			.scopes(scopes == null ? null : new HashSet<>((List<String>) scopes))
			.build();

		registeredClientBuilder.authorizationGrantType(authorizationGrantType);

		RegisteredClient registeredClient = registeredClientBuilder.build();

		Object principal = null;
		Object principalObject = attributesMap.get(Principal.class.getName());
		attributesMap.remove(Principal.class.getName());
		if (principalObject != null) {
			PrincipalObj principalObj = OBJECT_MAPPER.convertValue(principalObject, PrincipalObj.class);
			//
			String name = principalObj.getName();
			Set<Map<String, String>> authoritiesSet = principalObj.getAuthorities();

			Set<GrantedAuthority> authorities = new HashSet<>();
			for (Map<String, String> map : authoritiesSet) {
				SimpleGrantedAuthority authority = OBJECT_MAPPER.convertValue(map.values().iterator().next(),
						SimpleGrantedAuthority.class);
				authorities.add(authority);
			}

			User user = new User(name, UUID.randomUUID().toString(), authorities);
			UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken
				.authenticated(user, null, authorities);

			Details details = principalObj.getDetails();
			String remoteAddress = details.getRemoteAddress();
			String sessionId = details.getSessionId();

			WebAuthenticationDetails webAuthenticationDetails = new WebAuthenticationDetails(remoteAddress, sessionId);
			usernamePasswordAuthenticationToken.setDetails(webAuthenticationDetails);
			usernamePasswordAuthenticationToken.eraseCredentials();

			principal = usernamePasswordAuthenticationToken;
		}

		OAuth2Authorization.Builder oauth2AuthorizationBuilder = OAuth2Authorization
			.withRegisteredClient(registeredClient)
			.id(id)
			.principalName(principalName)
			.authorizedScopes(authorizedScopes)
			.authorizationGrantType(authorizationGrantType)
			.attribute(OAuth2AuthorizationRequest.class.getName(), oauth2AuthorizationRequest)
			.attribute(Principal.class.getName(), principal);

		if (accessToken != null) {
			oauth2AuthorizationBuilder.accessToken(accessToken);
		}

		if (refreshToken != null) {
			oauth2AuthorizationBuilder.refreshToken(refreshToken);
		}

		for (String key : attributesMap.keySet()) {
			oauth2AuthorizationBuilder.attribute(key, attributesMap.get(key));
		}

		return oauth2AuthorizationBuilder.build();
	}

	private OAuth2AccessToken accessToken(JsonParser p) throws IOException {

		TreeNode treeNode = p.readValueAsTree();

		OAuth2Token oauth2Token = OBJECT_MAPPER.convertValue(treeNode, OAuth2Token.class);

		if (oauth2Token == null) {
			return null;
		}

		Token token = oauth2Token.getToken();
		Map<String, Object> metadata = oauth2Token.getMetadata();
		boolean isActive = oauth2Token.isActive();
		boolean isExpired = oauth2Token.isExpired();
		Map<String, Object> claims = oauth2Token.getClaims();
		boolean isBeforeUse = oauth2Token.isBeforeUse();
		boolean isInvalidated = oauth2Token.isInvalidated();

		String tokenValue = token.getTokenValue();
		Map<String, String> tokenTypeMap = token.getTokenType();
		Set<String> scopes = token.getScopes();
		Long issuedAtSecond = token.getIssuedAtSecond();
		Long issuedAtNano = token.getIssuedAtNano();
		Long expiresAtSecond = token.getExpiresAtSecond();
		Long expiresAtNano = token.getExpiresAtNano();

		Instant issuedAt = Instant.ofEpochSecond(issuedAtSecond, issuedAtNano);
		Instant expiresAt = Instant.ofEpochSecond(expiresAtSecond, expiresAtNano);

		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue, issuedAt, expiresAt, scopes);
	}

	private OAuth2RefreshToken refreshToken(JsonParser p) throws IOException {
		TreeNode treeNode = p.readValueAsTree();

		OAuth2Token oauth2Token = OBJECT_MAPPER.convertValue(treeNode, OAuth2Token.class);

		if (oauth2Token == null) {
			return null;
		}

		Token token = oauth2Token.getToken();
		Map<String, Object> metadata = oauth2Token.getMetadata();
		boolean isActive = oauth2Token.isActive();
		boolean isExpired = oauth2Token.isExpired();
		Map<String, Object> claims = oauth2Token.getClaims();
		boolean isBeforeUse = oauth2Token.isBeforeUse();
		boolean isInvalidated = oauth2Token.isInvalidated();

		String tokenValue = token.getTokenValue();
		Map<String, String> tokenTypeMap = token.getTokenType();
		Set<String> scopes = token.getScopes();
		Long issuedAtSecond = token.getIssuedAtSecond();
		Long issuedAtNano = token.getIssuedAtNano();
		Long expiresAtSecond = token.getExpiresAtSecond();
		Long expiresAtNano = token.getExpiresAtNano();

		Instant issuedAt = Instant.ofEpochSecond(issuedAtSecond, issuedAtNano);
		Instant expiresAt = Instant.ofEpochSecond(expiresAtSecond, expiresAtNano);

		return new OAuth2RefreshToken(tokenValue, issuedAt, expiresAt);
	}

	/**
	 * @author xuxiaowei
	 * @since 2.0.0
	 */
	@Data
	private static class OAuth2Token {

		private Token token;

		private Map<String, Object> metadata;

		private boolean active;

		private boolean expired;

		private Map<String, Object> claims;

		private boolean beforeUse;

		private boolean invalidated;

	}

	/**
	 * @author xuxiaowei
	 * @since 2.0.0
	 */
	@Data
	private static class Token {

		private String tokenValue;

		private Map<String, String> tokenType;

		private Set<String> scopes;

		private BigDecimal issuedAt;

		private Long issuedAtSecond;

		private Long issuedAtNano;

		private BigDecimal expiresAt;

		private Long expiresAtSecond;

		private Long expiresAtNano;

		public void setIssuedAt(BigDecimal issuedAt) {
			this.issuedAt = issuedAt;
			BigDecimal issuedAtSecondBigDecimal = issuedAt.setScale(0, RoundingMode.DOWN);
			this.issuedAtSecond = issuedAtSecondBigDecimal.longValue();
			this.issuedAtNano = (issuedAt.subtract(issuedAtSecondBigDecimal).multiply(BigDecimal.valueOf(1000000000)))
				.longValue();
		}

		public void setExpiresAt(BigDecimal expiresAt) {
			this.expiresAt = expiresAt;
			BigDecimal expiresAtSecondBigDecimal = expiresAt.setScale(0, RoundingMode.DOWN);
			this.expiresAtSecond = expiresAtSecondBigDecimal.longValue();
			this.expiresAtNano = (expiresAt.subtract(expiresAtSecondBigDecimal)
				.multiply(BigDecimal.valueOf(1000000000))).longValue();
		}

	}

	/**
	 * @author xuxiaowei
	 * @since 2.0.0
	 */
	@Data
	private static class PrincipalObj {

		private Set<Map<String, String>> authorities;

		private Details details;

		private boolean authenticated;

		private PrincipalUser principal;

		private Object credentials;

		private String name;

	}

	/**
	 * @author xuxiaowei
	 * @since 2.0.0
	 */
	@Data
	private static class Details {

		private String remoteAddress;

		private String sessionId;

	}

	/**
	 * @author xuxiaowei
	 * @since 2.0.0
	 */
	@Data
	private static class PrincipalUser {

		private String password;

		private String username;

		private Set<Map<String, String>> authorities;

		private boolean accountNonExpired;

		private boolean accountNonLocked;

		private boolean credentialsNonExpired;

		private boolean enabled;

	}

}
