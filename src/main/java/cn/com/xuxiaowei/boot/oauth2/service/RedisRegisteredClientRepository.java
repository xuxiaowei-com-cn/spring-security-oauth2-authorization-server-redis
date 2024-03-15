package cn.com.xuxiaowei.boot.oauth2.service;

import cn.com.xuxiaowei.boot.oauth2.deserializer.AuthorizationGrantTypeDeserializer;
import cn.com.xuxiaowei.boot.oauth2.deserializer.ClientAuthenticationMethodDeserializer;
import cn.com.xuxiaowei.boot.oauth2.deserializer.ClientSettingsDeserializer;
import cn.com.xuxiaowei.boot.oauth2.deserializer.TokenSettingsDeserializer;
import cn.com.xuxiaowei.boot.oauth2.properties.SpringAuthorizationServerRedisProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.Getter;
import lombok.Setter;
import lombok.SneakyThrows;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.concurrent.TimeUnit;

/**
 * @author xuxiaowei
 * @since 2.0.0
 */
public class RedisRegisteredClientRepository implements RegisteredClientRepository {

	private final SpringAuthorizationServerRedisProperties properties;

	private final JdbcRegisteredClientRepository jdbcRegisteredClientRepository;

	private final StringRedisTemplate stringRedisTemplate;

	@Setter
	@Getter
	private ObjectMapper objectMapper = new ObjectMapper();

	public RedisRegisteredClientRepository(JdbcOperations jdbcOperations, StringRedisTemplate stringRedisTemplate,
			SpringAuthorizationServerRedisProperties properties) {
		this.jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcOperations);
		this.stringRedisTemplate = stringRedisTemplate;
		this.properties = properties;

		SimpleModule simpleModule = new SimpleModule();
		simpleModule.addDeserializer(ClientAuthenticationMethod.class, new ClientAuthenticationMethodDeserializer());
		simpleModule.addDeserializer(AuthorizationGrantType.class, new AuthorizationGrantTypeDeserializer());
		simpleModule.addDeserializer(ClientSettings.class, new ClientSettingsDeserializer());
		simpleModule.addDeserializer(TokenSettings.class, new TokenSettingsDeserializer());

		objectMapper.registerModules(new JavaTimeModule(), simpleModule);
	}

	@SneakyThrows
	@Override
	public void save(RegisteredClient registeredClient) {
		jdbcRegisteredClientRepository.save(registeredClient);

		long timeout = properties.getRegisteredClientTimeout();

		String json = objectMapper.writeValueAsString(registeredClient);

		String id = registeredClient.getId();
		String clientId = registeredClient.getClientId();

		String idKey = idKey(id);
		String clientIdKey = clientIdKey(clientId);

		stringRedisTemplate.opsForValue().set(idKey, json, timeout, TimeUnit.SECONDS);
		stringRedisTemplate.opsForValue().set(clientIdKey, json, timeout, TimeUnit.SECONDS);
	}

	@SneakyThrows
	@Override
	public RegisteredClient findById(String id) {

		long timeout = properties.getRegisteredClientTimeout();

		String idKey = idKey(id);

		String json = stringRedisTemplate.opsForValue().getAndExpire(idKey, timeout, TimeUnit.SECONDS);

		RegisteredClient registeredClient;

		if (json == null) {
			registeredClient = jdbcRegisteredClientRepository.findById(id);

			if (registeredClient != null) {
				json = objectMapper.writeValueAsString(registeredClient);

				stringRedisTemplate.opsForValue().set(idKey, json, timeout, TimeUnit.SECONDS);
			}
		}
		else {
			registeredClient = objectMapper.readValue(json, RegisteredClient.class);
		}

		if (registeredClient != null) {
			String clientIdKey = clientIdKey(registeredClient.getClientId());

			stringRedisTemplate.opsForValue().set(clientIdKey, json, timeout, TimeUnit.SECONDS);
		}

		return registeredClient;
	}

	@SneakyThrows
	@Override
	public RegisteredClient findByClientId(String clientId) {

		long timeout = properties.getRegisteredClientTimeout();

		String clientIdKey = clientIdKey(clientId);

		String json = stringRedisTemplate.opsForValue().getAndExpire(clientIdKey, timeout, TimeUnit.SECONDS);

		RegisteredClient registeredClient;

		if (json == null) {
			registeredClient = jdbcRegisteredClientRepository.findByClientId(clientId);

			if (registeredClient != null) {
				json = objectMapper.writeValueAsString(registeredClient);

				stringRedisTemplate.opsForValue().set(clientIdKey, json, timeout, TimeUnit.SECONDS);
			}
		}
		else {
			registeredClient = objectMapper.readValue(json, RegisteredClient.class);
		}

		if (registeredClient != null) {
			String idKey = idKey(registeredClient.getId());

			stringRedisTemplate.opsForValue().set(idKey, json, timeout, TimeUnit.SECONDS);
		}

		return registeredClient;
	}

	public String idKey(String id) {
		String prefix = properties.getPrefix();
		return prefix + ":oauth2_registered_client:id:" + id;
	}

	public String clientIdKey(String clientId) {
		String prefix = properties.getPrefix();
		return prefix + ":oauth2_registered_client:clientId:" + clientId;
	}

}