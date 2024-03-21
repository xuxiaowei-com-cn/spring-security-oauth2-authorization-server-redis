package cn.com.xuxiaowei.boot.oauth2.service;

import cn.com.xuxiaowei.boot.oauth2.deserializer.AuthorizationGrantTypeDeserializer;
import cn.com.xuxiaowei.boot.oauth2.deserializer.OAuth2AuthorizationDeserializer;
import cn.com.xuxiaowei.boot.oauth2.properties.SpringAuthorizationServerRedisProperties;
import cn.com.xuxiaowei.boot.oauth2.utils.RedisRuntimeException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.crypto.password.AlgorithmUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 表 oauth2_authorization 的 Redis 实现
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Slf4j
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

	public static final String TABLE_NAME = "oauth2_authorization";

	private final JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService;

	private final RegisteredClientRepository registeredClientRepository;

	private final StringRedisTemplate stringRedisTemplate;

	private final SpringAuthorizationServerRedisProperties properties;

	@Setter
	@Getter
	private ObjectMapper objectMapper = new ObjectMapper();

	public RedisOAuth2AuthorizationService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
			SpringAuthorizationServerRedisProperties properties) {
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcOperations,
				registeredClientRepository);
		this.registeredClientRepository = registeredClientRepository;
		this.stringRedisTemplate = stringRedisTemplate;
		this.properties = properties;

		registerModules();
	}

	public RedisOAuth2AuthorizationService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
			SpringAuthorizationServerRedisProperties properties, LobHandler lobHandler) {
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcOperations,
				registeredClientRepository, lobHandler);
		this.registeredClientRepository = registeredClientRepository;
		this.stringRedisTemplate = stringRedisTemplate;
		this.properties = properties;

		registerModules();
	}

	private void registerModules() {
		SimpleModule simpleModule = new SimpleModule();
		simpleModule.addDeserializer(AuthorizationGrantType.class, new AuthorizationGrantTypeDeserializer());
		simpleModule.addDeserializer(OAuth2Authorization.class, new OAuth2AuthorizationDeserializer());

		objectMapper.registerModules(new JavaTimeModule(), simpleModule);
	}

	@SneakyThrows
	@Override
	public void save(OAuth2Authorization authorization) {

		jdbcOAuth2AuthorizationService.save(authorization);

		String registeredClientId = authorization.getRegisteredClientId();
		RegisteredClient registeredClient = registeredClientRepository.findById(registeredClientId);

		TokenSettings tokenSettings = registeredClient.getTokenSettings();
		Duration authorizationCodeTimeToLive = tokenSettings.getAuthorizationCodeTimeToLive();
		Duration accessTokenTimeToLive = tokenSettings.getAccessTokenTimeToLive();
		Duration refreshTokenTimeToLive = tokenSettings.getRefreshTokenTimeToLive();

		long timeout = max(authorizationCodeTimeToLive.getSeconds(), accessTokenTimeToLive.getSeconds(),
				refreshTokenTimeToLive.getSeconds());

		String json = objectMapper.writeValueAsString(authorization);
		Map<String, String> map = new HashMap<>();
		map.put("id", json);

		// 需要处理的数据
		OAuth2Authorization.Token<OidcIdToken> oidcIdTokenToken = authorization.getToken(OidcIdToken.class);
		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		OAuth2Authorization.Token<OAuth2AuthorizationCode> oauth2AuthorizationCodeToken = authorization
			.getToken(OAuth2AuthorizationCode.class);

		// 需要合并到 Map 的数据
		if (oauth2AuthorizationCodeToken != null) {
			String authorizationCode = objectMapper.writeValueAsString(oauth2AuthorizationCodeToken);
			map.put(OAuth2AuthorizationCode.class.getSimpleName(), authorizationCode);
		}
		if (oidcIdTokenToken != null) {
			String oidcIdToken = objectMapper.writeValueAsString(oidcIdTokenToken);
			map.put(OidcIdToken.class.getSimpleName(), oidcIdToken);
		}

		String id = authorization.getId();
		String idKey = idKey(id);

		stringRedisTemplate.opsForHash().putAll(idKey, map);
		stringRedisTemplate.expire(idKey, timeout, TimeUnit.SECONDS);

		if (oauth2AuthorizationCodeToken != null) {
			String tokenValue = oauth2AuthorizationCodeToken.getToken().getTokenValue();
			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.CODE), tokenValue);

			stringRedisTemplate.opsForValue().set(tokenKey, id, authorizationCodeTimeToLive);
		}

		if (oidcIdTokenToken != null) {
			String tokenValue = oidcIdTokenToken.getToken().getTokenValue();
			String tokenKey = tokenKey(new OAuth2TokenType(OidcIdToken.class.getSimpleName()), tokenValue);

			stringRedisTemplate.opsForValue().set(tokenKey, id, timeout, TimeUnit.SECONDS);
		}

		if (accessToken != null) {
			String tokenValue = accessToken.getToken().getTokenValue();
			String tokenKey = tokenKey(OAuth2TokenType.ACCESS_TOKEN, tokenValue);

			stringRedisTemplate.opsForValue().set(tokenKey, id, accessTokenTimeToLive);
		}

		if (refreshToken != null) {
			String tokenValue = refreshToken.getToken().getTokenValue();
			String tokenKey = tokenKey(OAuth2TokenType.REFRESH_TOKEN, tokenValue);

			stringRedisTemplate.opsForValue().set(tokenKey, id, refreshTokenTimeToLive);
		}

		Object state = authorization.getAttribute(OAuth2ParameterNames.STATE);
		if (state != null) {
			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.STATE), state.toString());

			stringRedisTemplate.opsForValue().set(tokenKey, id, authorizationCodeTimeToLive);
		}
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		jdbcOAuth2AuthorizationService.remove(authorization);

		String id = authorization.getId();
		String idKey = idKey(id);

		stringRedisTemplate.delete(idKey);

		OAuth2Authorization.Token<OAuth2AuthorizationCode> oauth2AuthorizationCodeToken = authorization
			.getToken(OAuth2AuthorizationCode.class);
		if (oauth2AuthorizationCodeToken != null) {
			String tokenValue = oauth2AuthorizationCodeToken.getToken().getTokenValue();
			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.CODE), tokenValue);

			stringRedisTemplate.delete(tokenKey);
		}

		OAuth2Authorization.Token<OidcIdToken> oidcIdTokenToken = authorization.getToken(OidcIdToken.class);
		if (oidcIdTokenToken != null) {
			String tokenValue = oidcIdTokenToken.getToken().getTokenValue();
			String tokenKey = tokenKey(new OAuth2TokenType(OidcIdToken.class.getSimpleName()), tokenValue);

			stringRedisTemplate.delete(tokenKey);
		}

		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
		if (accessToken != null) {
			String tokenValue = accessToken.getToken().getTokenValue();
			String tokenKey = tokenKey(OAuth2TokenType.ACCESS_TOKEN, tokenValue);

			stringRedisTemplate.delete(tokenKey);
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (refreshToken != null) {
			String tokenValue = refreshToken.getToken().getTokenValue();
			String tokenKey = tokenKey(OAuth2TokenType.REFRESH_TOKEN, tokenValue);

			stringRedisTemplate.delete(tokenKey);
		}

		Object state = authorization.getAttribute(OAuth2ParameterNames.STATE);
		if (state != null) {

			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.STATE), state.toString());

			stringRedisTemplate.delete(tokenKey);
		}
	}

	@SneakyThrows
	@Override
	public OAuth2Authorization findById(String id) {

		String idKey = idKey(id);

		Map<Object, Object> entries = stringRedisTemplate.opsForHash().entries(idKey);

		OAuth2Authorization authorization;

		if (entries.isEmpty()) {
			authorization = jdbcOAuth2AuthorizationService.findById(id);
		}
		else {
			Object idValue = entries.get("id");
			Object authorizationCodeObj = entries.get(OAuth2AuthorizationCode.class.getSimpleName());
			Object oidcIdTokenObj = entries.get(OidcIdToken.class.getSimpleName());

			authorization = objectMapper.readValue(idValue.toString(), OAuth2Authorization.class);

			OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization);

			if (authorizationCodeObj != null) {
				builder.token(oauth2AuthorizationCode(authorizationCodeObj.toString()));
			}

			if (oidcIdTokenObj != null) {
				builder.token(oidcIdToken(oidcIdTokenObj.toString()));
			}

			authorization = builder.build();
		}

		return authorization;
	}

	@SneakyThrows
	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {

		String id;
		OAuth2Authorization authorization = null;

		if (new OAuth2TokenType(OAuth2ParameterNames.CODE).equals(tokenType)) {

			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.CODE), token);

			id = stringRedisTemplate.opsForValue().get(tokenKey);

			if (id == null) {
				authorization = jdbcOAuth2AuthorizationService.findByToken(token, tokenType);
			}
		}
		else if (new OAuth2TokenType(OidcIdToken.class.getSimpleName()).equals(tokenType)) {

			String tokenKey = tokenKey(new OAuth2TokenType(OidcIdToken.class.getSimpleName()), token);

			id = stringRedisTemplate.opsForValue().get(tokenKey);

			if (id == null) {
				authorization = jdbcOAuth2AuthorizationService.findByToken(token, tokenType);
			}
		}
		else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
			String tokenKey = tokenKey(OAuth2TokenType.ACCESS_TOKEN, token);

			id = stringRedisTemplate.opsForValue().get(tokenKey);

			if (id == null) {
				authorization = jdbcOAuth2AuthorizationService.findByToken(token, tokenType);
			}
		}
		else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
			String tokenKey = tokenKey(OAuth2TokenType.REFRESH_TOKEN, token);

			id = stringRedisTemplate.opsForValue().get(tokenKey);

			if (id == null) {
				authorization = jdbcOAuth2AuthorizationService.findByToken(token, tokenType);
			}
		}
		else if (new OAuth2TokenType(OAuth2ParameterNames.STATE).equals(tokenType)) {
			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.STATE), token);

			id = stringRedisTemplate.opsForValue().get(tokenKey);

			if (id == null) {
				authorization = jdbcOAuth2AuthorizationService.findByToken(token, tokenType);
			}
		}
		else {

			throw new RedisRuntimeException("不支持的类型：" + tokenType);
		}

		if (authorization != null) {
			return authorization;
		}

		if (id == null) {
			return null;
		}

		String idKey = idKey(id);

		Map<Object, Object> entries = stringRedisTemplate.opsForHash().entries(idKey);

		Object idValue = entries.get("id");
		authorization = objectMapper.readValue(idValue.toString(), OAuth2Authorization.class);

		Object authorizationCodeObj = entries.get(OAuth2AuthorizationCode.class.getSimpleName());
		if (authorizationCodeObj != null) {
			authorization = OAuth2Authorization.from(authorization)
				.token(oauth2AuthorizationCode(authorizationCodeObj.toString()))
				.build();
		}

		Object oidcIdTokenObj = entries.get(OidcIdToken.class.getSimpleName());
		if (oidcIdTokenObj != null) {
			authorization = OAuth2Authorization.from(authorization)
				.token(oidcIdToken(oidcIdTokenObj.toString()))
				.build();
		}

		return authorization;
	}

	private OidcIdToken oidcIdToken(String str) throws JsonProcessingException {
		OAuth2AuthorizationDeserializer.OAuth2Token oauth2Token = objectMapper.readValue(str,
				OAuth2AuthorizationDeserializer.OAuth2Token.class);

		OAuth2AuthorizationDeserializer.Token oidcIdToken = oauth2Token.getToken();
		String tokenValue = oidcIdToken.getTokenValue();
		Long issuedAtSecond = oidcIdToken.getIssuedAtSecond();
		Long issuedAtNano = oidcIdToken.getIssuedAtNano();
		Long expiresAtSecond = oidcIdToken.getExpiresAtSecond();
		Long expiresAtNano = oidcIdToken.getExpiresAtNano();
		Instant issuedAt = Instant.ofEpochSecond(issuedAtSecond, issuedAtNano);
		Instant expiresAt = Instant.ofEpochSecond(expiresAtSecond, expiresAtNano);

		Map<String, Object> claims = oauth2Token.getClaims();
		claims.put(IdTokenClaimNames.IAT, issuedAt);
		claims.put(IdTokenClaimNames.EXP, expiresAt);

		return OidcIdToken.withTokenValue(tokenValue).claims(claimsConsumer -> claimsConsumer.putAll(claims)).build();
	}

	private OAuth2AuthorizationCode oauth2AuthorizationCode(String str) throws JsonProcessingException {
		// @formatter:off
		OAuth2AuthorizationDeserializer.OAuth2Token oauth2Token = objectMapper.readValue(str, OAuth2AuthorizationDeserializer.OAuth2Token.class);
		OAuth2AuthorizationDeserializer.Token tokenCode = oauth2Token.getToken();
		String tokenValue = tokenCode.getTokenValue();
		Long issuedAtSecond = tokenCode.getIssuedAtSecond();
		Long issuedAtNano = tokenCode.getIssuedAtNano();
		Long expiresAtSecond = tokenCode.getExpiresAtSecond();
		Long expiresAtNano = tokenCode.getExpiresAtNano();
		Instant issuedAt = Instant.ofEpochSecond(issuedAtSecond, issuedAtNano);
		Instant expiresAt = Instant.ofEpochSecond(expiresAtSecond, expiresAtNano);
		return new OAuth2AuthorizationCode(tokenValue, issuedAt, expiresAt);
		// @formatter:on
	}

	public String idKey(String id) {
		String prefix = properties.getPrefix();
		return String.format("%s:%s:id:%s", prefix, TABLE_NAME, id);
	}

	public String tokenKey(OAuth2TokenType tokenType, String token) {
		String prefix = properties.getPrefix();
		AlgorithmUtils.Algorithm algorithm = properties.getAlgorithm();

		// 用于缩短 key
		AlgorithmUtils algorithmUtils = new AlgorithmUtils(algorithm);

		String encode = algorithmUtils.encode(token);

		return String.format("%s:%s:%s:%s", prefix, TABLE_NAME, tokenType.getValue(), encode);
	}

	private long max(long... nums) {
		long max = nums[0];
		for (int i = 1; i < nums.length; i++) {
			if (nums[i] > max) {
				max = nums[i];
			}
		}
		return max;
	}

}