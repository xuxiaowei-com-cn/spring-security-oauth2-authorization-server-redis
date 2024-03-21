package cn.com.xuxiaowei.boot.oauth2.service;

import cn.com.xuxiaowei.boot.oauth2.constant.RedisConstants;
import cn.com.xuxiaowei.boot.oauth2.deserializer.AuthorizationGrantTypeDeserializer;
import cn.com.xuxiaowei.boot.oauth2.deserializer.OAuth2AuthorizationDeserializer;
import cn.com.xuxiaowei.boot.oauth2.properties.SpringAuthorizationServerRedisProperties;
import cn.com.xuxiaowei.boot.oauth2.utils.RedisRuntimeException;
import cn.com.xuxiaowei.boot.oauth2.utils.RedisUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.crypto.password.AlgorithmUtils;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
		save(authorization, true);
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

		long timeout = properties.getAuthorizationTimeout();

		String idKey = idKey(id);

		String redisVersion = RedisUtils.redisVersion(stringRedisTemplate);
		int compare = StringUtils.compare(redisVersion, RedisConstants.GETEX_VERSION);

		String json;

		if (compare < 0) {
			log.warn("警告：Redis 版本低于 {}，不支持 GETEX（getAndExpire）命令", RedisConstants.GETEX_VERSION);

			json = stringRedisTemplate.opsForValue().get(idKey);

			if (json != null) {
				stringRedisTemplate.expire(idKey, timeout, TimeUnit.SECONDS);
			}
		}
		else {
			json = stringRedisTemplate.opsForValue().getAndExpire(idKey, timeout, TimeUnit.SECONDS);
		}

		OAuth2Authorization authorization;

		if (json == null) {
			authorization = jdbcOAuth2AuthorizationService.findById(id);
		}
		else {
			authorization = objectMapper.readValue(json, OAuth2Authorization.class);
		}

		if (authorization != null) {
			save(authorization, false);
		}

		return authorization;
	}

	@SneakyThrows
	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {

		OAuth2Authorization authorization;

		if (new OAuth2TokenType(OAuth2ParameterNames.CODE).equals(tokenType)) {

			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.CODE), token);

			Map<Object, Object> entries = stringRedisTemplate.opsForHash().entries(tokenKey);

			Object idValue = entries.get("id");
			authorization = objectMapper.readValue(idValue.toString(), OAuth2Authorization.class);

			// @formatter:off
            Object authorizationCodeObj = entries.get(OAuth2AuthorizationCode.class.getSimpleName());
            OAuth2AuthorizationDeserializer.OAuth2Token oauth2Token = objectMapper.readValue(authorizationCodeObj.toString(), OAuth2AuthorizationDeserializer.OAuth2Token.class);
            OAuth2AuthorizationDeserializer.Token tokenCode = oauth2Token.getToken();
            String tokenValue = tokenCode.getTokenValue();
            Long issuedAtSecond = tokenCode.getIssuedAtSecond();
            Long issuedAtNano = tokenCode.getIssuedAtNano();
            Long expiresAtSecond = tokenCode.getExpiresAtSecond();
            Long expiresAtNano = tokenCode.getExpiresAtNano();
            Instant issuedAt = Instant.ofEpochSecond(issuedAtSecond, issuedAtNano);
            Instant expiresAt = Instant.ofEpochSecond(expiresAtSecond, expiresAtNano);
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(tokenValue, issuedAt, expiresAt);
            authorization = OAuth2Authorization.from(authorization).token(authorizationCode).build();
            // @formatter:on
		}
		else if (new OAuth2TokenType(OidcIdToken.class.getSimpleName()).equals(tokenType)) {

			String tokenKey = tokenKey(new OAuth2TokenType(OidcIdToken.class.getSimpleName()), token);

			Map<Object, Object> entries = stringRedisTemplate.opsForHash().entries(tokenKey);

			Object idValue = entries.get("id");
			authorization = objectMapper.readValue(idValue.toString(), OAuth2Authorization.class);

			Object oidcIdTokenObj = entries.get(OidcIdToken.class.getSimpleName());
			OidcIdToken oidcIdToken = objectMapper.readValue(oidcIdTokenObj.toString(), OidcIdToken.class);
			authorization = OAuth2Authorization.from(authorization).token(oidcIdToken).build();
		}
		else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
			String tokenKey = tokenKey(OAuth2TokenType.ACCESS_TOKEN, token);

			String json = stringRedisTemplate.opsForValue().get(tokenKey);
			authorization = objectMapper.readValue(json, OAuth2Authorization.class);
		}
		else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
			String tokenKey = tokenKey(OAuth2TokenType.REFRESH_TOKEN, token);

			String json = stringRedisTemplate.opsForValue().get(tokenKey);
			authorization = objectMapper.readValue(json, OAuth2Authorization.class);
		}
		else if (new OAuth2TokenType(OAuth2ParameterNames.STATE).equals(tokenType)) {
			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.STATE), token);

			String json = stringRedisTemplate.opsForValue().get(tokenKey);
			authorization = objectMapper.readValue(json, OAuth2Authorization.class);
		}
		else {

			throw new RedisRuntimeException("不支持的类型：" + tokenType);
		}

		return authorization;
	}

	public void save(OAuth2Authorization authorization, boolean jdbc) throws JsonProcessingException {
		if (jdbc) {
			jdbcOAuth2AuthorizationService.save(authorization);
		}

		long timeout = properties.getAuthorizationTimeout();

		String registeredClientId = authorization.getRegisteredClientId();
		RegisteredClient registeredClient = registeredClientRepository.findById(registeredClientId);

		String json = objectMapper.writeValueAsString(authorization);

		String id = authorization.getId();
		String idKey = idKey(id);

		stringRedisTemplate.opsForValue().set(idKey, json, timeout, TimeUnit.SECONDS);

		OAuth2Authorization.Token<OAuth2AuthorizationCode> oauth2AuthorizationCodeToken = authorization
			.getToken(OAuth2AuthorizationCode.class);
		if (oauth2AuthorizationCodeToken != null) {
			TokenSettings tokenSettings = registeredClient.getTokenSettings();
			Duration authorizationCodeTimeToLive = tokenSettings.getAuthorizationCodeTimeToLive();

			String tokenValue = oauth2AuthorizationCodeToken.getToken().getTokenValue();
			String authorizationCode = objectMapper.writeValueAsString(oauth2AuthorizationCodeToken);
			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.CODE), tokenValue);

			Map<String, String> map = new HashMap<>();
			map.put("id", json);
			map.put(OAuth2AuthorizationCode.class.getSimpleName(), authorizationCode);

			stringRedisTemplate.opsForHash().putAll(tokenKey, map);
			stringRedisTemplate.expire(tokenKey, authorizationCodeTimeToLive);
		}

		OAuth2Authorization.Token<OidcIdToken> oidcIdTokenToken = authorization.getToken(OidcIdToken.class);
		if (oidcIdTokenToken != null) {
			String tokenValue = oidcIdTokenToken.getToken().getTokenValue();
			String oidcIdToken = objectMapper.writeValueAsString(oidcIdTokenToken);
			String tokenKey = tokenKey(new OAuth2TokenType(OidcIdToken.class.getSimpleName()), tokenValue);

			Map<String, String> map = new HashMap<>();
			map.put("id", json);
			map.put(OidcIdToken.class.getSimpleName(), oidcIdToken);

			stringRedisTemplate.opsForHash().putAll(tokenKey, map);
			stringRedisTemplate.expire(tokenKey, timeout, TimeUnit.SECONDS);
		}

		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
		if (accessToken != null) {
			TokenSettings tokenSettings = registeredClient.getTokenSettings();
			Duration refreshTokenTimeToLive = tokenSettings.getRefreshTokenTimeToLive();

			String tokenValue = accessToken.getToken().getTokenValue();
			String tokenKey = tokenKey(OAuth2TokenType.ACCESS_TOKEN, tokenValue);

			stringRedisTemplate.opsForValue().set(tokenKey, json, refreshTokenTimeToLive);
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (refreshToken != null) {
			TokenSettings tokenSettings = registeredClient.getTokenSettings();
			Duration refreshTokenTimeToLive = tokenSettings.getRefreshTokenTimeToLive();

			String tokenValue = refreshToken.getToken().getTokenValue();
			String tokenKey = tokenKey(OAuth2TokenType.REFRESH_TOKEN, tokenValue);

			stringRedisTemplate.opsForValue().set(tokenKey, json, refreshTokenTimeToLive);
		}

		Object state = authorization.getAttribute(OAuth2ParameterNames.STATE);
		if (state != null) {
			TokenSettings tokenSettings = registeredClient.getTokenSettings();
			Duration authorizationCodeTimeToLive = tokenSettings.getAuthorizationCodeTimeToLive();

			String tokenKey = tokenKey(new OAuth2TokenType(OAuth2ParameterNames.STATE), state.toString());

			stringRedisTemplate.opsForValue().set(tokenKey, json, authorizationCodeTimeToLive);
		}
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

}