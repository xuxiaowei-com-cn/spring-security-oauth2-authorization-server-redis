package org.springframework.security.oauth2.server.authorization.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.lang.NonNull;

import javax.sql.DataSource;
import java.util.concurrent.TimeUnit;

/**
 * 一个 Redis 的 {@link RegisteredClientRepository} 实现
 *
 * @author xuxiaowei
 * @since 0.0.1
 * @see InMemoryRegisteredClientRepository
 * @see JdbcRegisteredClientRepository
 */
@Slf4j
public class RedisRegisteredClientRepository implements RegisteredClientRepository {

	/**
	 *
	 */
	public static final String REGISTERED_CLIENT_ID = "registered_client:id:";

	/**
	 *
	 */
	public static final String REGISTERED_CLIENT_CLIENT_ID = "registered_client:clientId:";

	private RedisTemplate<String, RegisteredClient> redisTemplate;

	private JdbcRegisteredClientRepository jdbcRegisteredClientRepository;

	@Autowired
	public void setRedisTemplate(
			@Qualifier(RedisRegisteredClientRepositoryConfiguration.REDIS_TEMPLATE_BEAN_NAME) RedisTemplate<String, RegisteredClient> redisTemplate) {
		this.redisTemplate = redisTemplate;
	}

	@Autowired
	public void setJdbcRegisteredClientRepository(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		this.jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
	}

	@Override
	public void save(RegisteredClient registeredClient) {
		if (registeredClient != null) {

			set(registeredClient, 60, TimeUnit.MINUTES);

			jdbcRegisteredClientRepository.save(registeredClient);
		}
	}

	@Override
	public RegisteredClient findById(String id) {

		RegisteredClient registeredClientByRedis = redisTemplate.opsForValue().get(REGISTERED_CLIENT_ID + id);

		RegisteredClient registeredClientResult;
		RegisteredClient registeredClientByDatabase;

		if (registeredClientByRedis == null) {
			registeredClientByDatabase = jdbcRegisteredClientRepository.findById(id);
			log.debug("根据 id：{} 直接查询数据库中的客户：{}", id, registeredClientByDatabase);

			if (registeredClientByDatabase != null) {
				set(registeredClientByDatabase, 60, TimeUnit.MINUTES);
			}

			registeredClientResult = registeredClientByDatabase;
		}
		else {
			log.debug("根据 id：{} 直接查询Redis中的客户：{}", id, registeredClientByRedis);
			registeredClientResult = registeredClientByRedis;
		}

		return registeredClientResult;
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		RegisteredClient registeredClientByRedis = redisTemplate.opsForValue()
			.get(REGISTERED_CLIENT_CLIENT_ID + clientId);

		RegisteredClient registeredClientResult;
		RegisteredClient registeredClientByDatabase;

		if (registeredClientByRedis == null) {
			registeredClientByDatabase = jdbcRegisteredClientRepository.findByClientId(clientId);
			log.debug("根据 clientId：{} 直接查询数据库中的客户：{}", clientId, registeredClientByDatabase);

			if (registeredClientByDatabase != null) {
				set(registeredClientByDatabase, 60, TimeUnit.MINUTES);
			}

			registeredClientResult = registeredClientByDatabase;
		}
		else {
			log.debug("根据 clientId：{} 直接查询Redis中的客户：{}", clientId, registeredClientByRedis);
			registeredClientResult = registeredClientByRedis;
		}

		return registeredClientResult;
	}

	public void set(@NonNull RegisteredClient registeredClient, long timeout, TimeUnit unit) {
		// @formatter:off
		redisTemplate.opsForValue().set(REGISTERED_CLIENT_ID + registeredClient.getId(), registeredClient, timeout, unit);
		redisTemplate.opsForValue().set(REGISTERED_CLIENT_CLIENT_ID + registeredClient.getClientId(), registeredClient, timeout, unit);
		// @formatter:on
	}

}
