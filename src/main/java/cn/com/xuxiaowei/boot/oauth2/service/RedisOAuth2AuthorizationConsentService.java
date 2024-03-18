package cn.com.xuxiaowei.boot.oauth2.service;

import cn.com.xuxiaowei.boot.oauth2.constant.RedisConstants;
import cn.com.xuxiaowei.boot.oauth2.deserializer.OAuth2AuthorizationConsentDeserializer;
import cn.com.xuxiaowei.boot.oauth2.properties.SpringAuthorizationServerRedisProperties;
import cn.com.xuxiaowei.boot.oauth2.utils.RedisUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.concurrent.TimeUnit;

/**
 * 表 oauth2_authorization_consent 的 Redis 实现
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Slf4j
public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	public static final String TABLE_NAME = "oauth2_authorization_consent";

	private final JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService;

	private final StringRedisTemplate stringRedisTemplate;

	private final SpringAuthorizationServerRedisProperties properties;

	@Setter
	@Getter
	private ObjectMapper objectMapper = new ObjectMapper();

	public RedisOAuth2AuthorizationConsentService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository, StringRedisTemplate stringRedisTemplate,
			SpringAuthorizationServerRedisProperties properties) {
		this.jdbcOAuth2AuthorizationConsentService = new JdbcOAuth2AuthorizationConsentService(jdbcOperations,
				registeredClientRepository);
		this.stringRedisTemplate = stringRedisTemplate;
		this.properties = properties;

		SimpleModule simpleModule = new SimpleModule();
		simpleModule.addDeserializer(OAuth2AuthorizationConsent.class, new OAuth2AuthorizationConsentDeserializer());

		objectMapper.registerModule(simpleModule);
	}

	@SneakyThrows
	@Override
	public void save(OAuth2AuthorizationConsent authorizationConsent) {
		jdbcOAuth2AuthorizationConsentService.save(authorizationConsent);

		long timeout = properties.getAuthorizationConsentTimeout();

		String json = objectMapper.writeValueAsString(authorizationConsent);

		String registeredClientId = authorizationConsent.getRegisteredClientId();
		String principalName = authorizationConsent.getPrincipalName();

		String key = key(registeredClientId, principalName);

		stringRedisTemplate.opsForValue().set(key, json, timeout, TimeUnit.SECONDS);
	}

	@Override
	public void remove(OAuth2AuthorizationConsent authorizationConsent) {
		jdbcOAuth2AuthorizationConsentService.remove(authorizationConsent);

		String registeredClientId = authorizationConsent.getRegisteredClientId();
		String principalName = authorizationConsent.getPrincipalName();

		String key = key(registeredClientId, principalName);

		stringRedisTemplate.delete(key);
	}

	@SneakyThrows
	@Override
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {

		String key = key(registeredClientId, principalName);

		long timeout = properties.getAuthorizationConsentTimeout();

		String redisVersion = RedisUtils.redisVersion(stringRedisTemplate);
		int compare = StringUtils.compare(redisVersion, RedisConstants.GETDEL_VERSION);

		String json;

		if (compare < 0) {
			log.warn("警告：Redis 版本低于 {}，不支持 GETEX（getAndExpire）命令", RedisConstants.GETEX_VERSION);

			json = stringRedisTemplate.opsForValue().get(key);

			if (json != null) {
				stringRedisTemplate.expire(key, timeout, TimeUnit.SECONDS);
			}
		}
		else {
			json = stringRedisTemplate.opsForValue().getAndExpire(key, timeout, TimeUnit.SECONDS);
		}

		OAuth2AuthorizationConsent oauth2AuthorizationConsent;

		if (json == null) {
			oauth2AuthorizationConsent = jdbcOAuth2AuthorizationConsentService.findById(registeredClientId,
					principalName);

			if (oauth2AuthorizationConsent != null) {

				json = objectMapper.writeValueAsString(oauth2AuthorizationConsent);

				stringRedisTemplate.opsForValue().set(key, json, timeout, TimeUnit.SECONDS);
			}
		}
		else {
			oauth2AuthorizationConsent = objectMapper.readValue(json, OAuth2AuthorizationConsent.class);
		}

		return oauth2AuthorizationConsent;
	}

	public String key(String registeredClientId, String principalName) {
		String prefix = properties.getPrefix();
		return String.format("%s:%s:%s:%s", prefix, TABLE_NAME, registeredClientId, principalName);
	}

}
