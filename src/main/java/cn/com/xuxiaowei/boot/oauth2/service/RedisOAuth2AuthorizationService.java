package cn.com.xuxiaowei.boot.oauth2.service;

import cn.com.xuxiaowei.boot.oauth2.constant.RedisConstants;
import cn.com.xuxiaowei.boot.oauth2.deserializer.AuthorizationGrantTypeDeserializer;
import cn.com.xuxiaowei.boot.oauth2.deserializer.OAuth2AuthorizationDeserializer;
import cn.com.xuxiaowei.boot.oauth2.properties.SpringAuthorizationServerRedisProperties;
import cn.com.xuxiaowei.boot.oauth2.utils.RedisUtils;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

/**
 * @author xuxiaowei
 * @since 2.0.0
 */
@Slf4j
public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

	private final JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService;

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
		this.stringRedisTemplate = stringRedisTemplate;
		this.properties = properties;

		registerModules();
	}

	public RedisOAuth2AuthorizationService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
			SpringAuthorizationServerRedisProperties properties, LobHandler lobHandler) {
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcOperations,
				registeredClientRepository, lobHandler);
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

		long timeout = properties.getAuthorizationTimeout();

		String json = objectMapper.writeValueAsString(authorization);

		OAuth2Authorization.Token<OAuth2AuthorizationCode> oauth2AuthorizationCodeToken = authorization
			.getToken(OAuth2AuthorizationCode.class);
		OAuth2Authorization.Token<OidcIdToken> oidcIdTokenToken = authorization.getToken(OidcIdToken.class);

		if (oauth2AuthorizationCodeToken != null) {

			String string = objectMapper.writeValueAsString(oauth2AuthorizationCodeToken);

			stringRedisTemplate.opsForValue()
				.set(tokenKey(oauth2AuthorizationCodeToken.getToken().getTokenValue(),
						new OAuth2TokenType(OAuth2ParameterNames.CODE)), string, timeout, TimeUnit.SECONDS);

			stringRedisTemplate.opsForValue()
				.set(codeTokenKey(oauth2AuthorizationCodeToken.getToken().getTokenValue(),
						new OAuth2TokenType(OAuth2ParameterNames.CODE)), json, timeout, TimeUnit.SECONDS);
		}

		if (oidcIdTokenToken != null) {

		}

		String idKey = idKey(authorization.getId());

		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
		if (accessToken != null) {
			String tokenValue = accessToken.getToken().getTokenValue();
			String tokenKey = tokenKey(tokenValue, OAuth2TokenType.ACCESS_TOKEN);

			stringRedisTemplate.opsForValue().set(tokenKey, json, timeout, TimeUnit.SECONDS);
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (refreshToken != null) {
			String tokenValue = refreshToken.getToken().getTokenValue();
			String tokenKey = tokenKey(tokenValue, OAuth2TokenType.REFRESH_TOKEN);

			stringRedisTemplate.opsForValue().set(tokenKey, json, timeout, TimeUnit.SECONDS);
		}

		if (accessToken == null && refreshToken == null) {
			Object state = authorization.getAttribute(OAuth2ParameterNames.STATE);
			if (state != null) {
				String tokenKey = tokenKey(state.toString(), new OAuth2TokenType(OAuth2ParameterNames.STATE));

				stringRedisTemplate.opsForValue().set(tokenKey, json, timeout, TimeUnit.SECONDS);
			}
		}

		stringRedisTemplate.opsForValue().set(idKey, json, timeout, TimeUnit.SECONDS);
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		jdbcOAuth2AuthorizationService.remove(authorization);

		String idKey = idKey(authorization.getId());

		OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
		if (accessToken != null) {
			String tokenValue = accessToken.getToken().getTokenValue();
			String tokenKey = tokenKey(tokenValue, OAuth2TokenType.ACCESS_TOKEN);
			stringRedisTemplate.delete(tokenKey);
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (refreshToken != null) {
			String tokenValue = refreshToken.getToken().getTokenValue();
			String tokenKey = tokenKey(tokenValue, OAuth2TokenType.REFRESH_TOKEN);
			stringRedisTemplate.delete(tokenKey);
		}

		stringRedisTemplate.delete(idKey);
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

			json = objectMapper.writeValueAsString(authorization);

			if (authorization != null) {
				OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
				if (accessToken != null) {
					String tokenValue = accessToken.getToken().getTokenValue();
					String tokenKey = tokenKey(tokenValue, OAuth2TokenType.ACCESS_TOKEN);

					stringRedisTemplate.opsForValue().set(tokenKey, json, timeout, TimeUnit.SECONDS);
				}

				OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
				if (refreshToken != null) {
					String tokenValue = refreshToken.getToken().getTokenValue();
					String tokenKey = tokenKey(tokenValue, OAuth2TokenType.REFRESH_TOKEN);

					stringRedisTemplate.opsForValue().set(tokenKey, json, timeout, TimeUnit.SECONDS);
				}

				stringRedisTemplate.opsForValue().set(idKey, json, timeout, TimeUnit.SECONDS);
			}
		}
		else {
			authorization = objectMapper.readValue(json, OAuth2Authorization.class);
		}

		return authorization;
	}

	@SneakyThrows
	@Override
	public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {

		String tokenKey;

		if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
			tokenKey = codeTokenKey(token, new OAuth2TokenType(OAuth2ParameterNames.CODE));
		}
		else {
			tokenKey = tokenKey(token, tokenType);
		}

		long timeout = properties.getAuthorizationTimeout();

		String redisVersion = RedisUtils.redisVersion(stringRedisTemplate);
		int compare = StringUtils.compare(redisVersion, RedisConstants.GETEX_VERSION);

		String json;

		if (compare < 0) {
			log.warn("警告：Redis 版本低于 {}，不支持 GETEX（getAndExpire）命令", RedisConstants.GETEX_VERSION);

			json = stringRedisTemplate.opsForValue().get(tokenKey);
		}
		else {
			json = stringRedisTemplate.opsForValue().getAndExpire(tokenKey, timeout, TimeUnit.SECONDS);
		}

		OAuth2Authorization authorization;

		if (json == null) {
			authorization = jdbcOAuth2AuthorizationService.findByToken(token, tokenType);

			if (authorization != null) {

				json = objectMapper.writeValueAsString(authorization);

				// @formatter:off
				stringRedisTemplate.opsForValue().set(idKey(authorization.getId()), json, timeout, TimeUnit.SECONDS);
				stringRedisTemplate.opsForValue().set(tokenKey(token, OAuth2TokenType.REFRESH_TOKEN), json, timeout, TimeUnit.SECONDS);
				stringRedisTemplate.opsForValue().set(tokenKey(token, OAuth2TokenType.ACCESS_TOKEN), json, timeout, TimeUnit.SECONDS);
				// @formatter:on
			}
		}
		else {
			authorization = objectMapper.readValue(json, OAuth2Authorization.class);

			if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {

				String string = stringRedisTemplate.opsForValue().get(tokenKey(token, tokenType));

				OAuth2AuthorizationDeserializer.OAuth2Token oauth2Token = objectMapper.readValue(string,
						OAuth2AuthorizationDeserializer.OAuth2Token.class);

				OAuth2AuthorizationDeserializer.Token tokenCode = oauth2Token.getToken();
				String tokenValue = tokenCode.getTokenValue();
				Long issuedAtSecond = tokenCode.getIssuedAtSecond();
				Long issuedAtNano = tokenCode.getIssuedAtNano();
				Long expiresAtSecond = tokenCode.getExpiresAtSecond();
				Long expiresAtNano = tokenCode.getExpiresAtNano();

				Instant issuedAt = Instant.ofEpochSecond(issuedAtSecond, issuedAtNano);
				Instant expiresAt = Instant.ofEpochSecond(expiresAtSecond, expiresAtNano);

				OAuth2AuthorizationCode oauth2AuthorizationCode = new OAuth2AuthorizationCode(tokenValue, issuedAt,
						expiresAt);

				authorization = OAuth2Authorization.from(authorization).token(oauth2AuthorizationCode).build();
			}

			stringRedisTemplate.expire(idKey(authorization.getId()), timeout, TimeUnit.SECONDS);
			stringRedisTemplate.expire(tokenKey(token, OAuth2TokenType.REFRESH_TOKEN), timeout, TimeUnit.SECONDS);
			stringRedisTemplate.expire(tokenKey(token, OAuth2TokenType.ACCESS_TOKEN), timeout, TimeUnit.SECONDS);
		}

		return authorization;
	}

	public String idKey(String id) {
		String prefix = properties.getPrefix();
		return prefix + ":oauth2_authorization:id:" + id;
	}

	public String tokenKey(String token, OAuth2TokenType tokenType) {
		String prefix = properties.getPrefix();
		return prefix + ":oauth2_authorization:token:" + tokenType.getValue() + ":" + token;
	}

	public String codeTokenKey(String token, OAuth2TokenType tokenType) {
		String prefix = properties.getPrefix();
		return prefix + ":oauth2_authorization:token:id:" + tokenType.getValue() + ":" + token;
	}

}
