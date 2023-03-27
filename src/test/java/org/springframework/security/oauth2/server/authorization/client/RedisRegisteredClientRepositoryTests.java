package org.springframework.security.oauth2.server.authorization.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.H2DataSourceTestConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.utils.ObjectMapperUtils;

import javax.sql.DataSource;

import static org.springframework.security.oauth2.server.authorization.H2DataSourceTestConfiguration.CLIENT_ID;
import static org.springframework.security.oauth2.server.authorization.H2DataSourceTestConfiguration.ID;

/**
 * {@link RedisRegisteredClientRepository} 测试类
 * <p>
 * 请修改Redis密码
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Import(H2DataSourceTestConfiguration.class)
@SpringBootTest(classes = { RedisAutoConfiguration.class, RedisRegisteredClientRepositoryConfiguration.class,
		RedisRegisteredClientRepository.class })
class RedisRegisteredClientRepositoryTests {

	@Autowired
	private RedisRegisteredClientRepository redisRegisteredClientRepository;

	/**
	 * 基于 JDBC 的 {@link RegisteredClientRepository}，用于直接操作数据库中的客户信息
	 */
	private JdbcRegisteredClientRepository jdbcRegisteredClientRepository;

	@Autowired
	public void setJdbcRegisteredClientRepository(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		this.jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
	}

	/**
	 * {@link BeforeEach}：在每个测试方法执行之前运行。
	 */
	@BeforeEach
	void beforeEach() {

	}

	/**
	 * {@link BeforeAll}：在所有测试方法执行之前运行，只能使用在静态方法中（static void）。
	 */
	@BeforeAll
	static void beforeAll() {

	}

	@Test
	void save() throws JsonProcessingException {
		String id = "123456";
		RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(id);
		// 客户ID
		registeredClientBuilder.clientId("admin");
		// 客户凭证
		registeredClientBuilder.clientSecret("{noop}123456");
		// 客户凭证验证方式
		registeredClientBuilder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		registeredClientBuilder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		// 授权类型
		registeredClientBuilder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
		registeredClientBuilder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
		registeredClientBuilder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
		// 授权成功后重定向地址
		registeredClientBuilder.redirectUri("http://127.0.0.1:1401/code");
		// 授权范围
		registeredClientBuilder.scope("snsapi_base");

		ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder();
		clientSettingsBuilder.requireAuthorizationConsent(true);
		ClientSettings clientSettings = clientSettingsBuilder.build();

		RegisteredClient registeredClient = registeredClientBuilder.clientSettings(clientSettings).build();

		redisRegisteredClientRepository.save(registeredClient);

		ObjectMapper objectMapper = ObjectMapperUtils.redis();

		RegisteredClient registeredClientByDatabase = jdbcRegisteredClientRepository.findById(id);
		log.info("直接查询数据库中的保存的结果：{}", objectMapper.writeValueAsString(registeredClientByDatabase));
	}

	@Test
	void findById() throws JsonProcessingException {
		ObjectMapper objectMapper = ObjectMapperUtils.redis();
		RegisteredClient clientRepositoryByRedis = redisRegisteredClientRepository.findById(ID);
		log.info("根据 id：{} 查询Redis中的客户（不存在时从数据库中查询）：{}", ID, objectMapper.writeValueAsString(clientRepositoryByRedis));
	}

	@Test
	void findByClientId() throws JsonProcessingException {
		ObjectMapper objectMapper = ObjectMapperUtils.redis();
		RegisteredClient registeredClient = jdbcRegisteredClientRepository.findByClientId(CLIENT_ID);
		log.info("根据 clientId：{} 直接查询数据库中的客户：{}", CLIENT_ID, objectMapper.writeValueAsString(registeredClient));
	}

}
