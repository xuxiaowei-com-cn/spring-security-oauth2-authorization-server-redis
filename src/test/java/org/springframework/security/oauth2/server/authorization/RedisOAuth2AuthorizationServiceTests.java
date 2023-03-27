package org.springframework.security.oauth2.server.authorization;

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
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.utils.ObjectMapperUtils;

import javax.sql.DataSource;

import static org.springframework.security.oauth2.server.authorization.H2DataSourceTestConfiguration.AUTHORIZATION_ID;
import static org.springframework.security.oauth2.server.authorization.H2DataSourceTestConfiguration.ID;

/**
 * {@link OAuth2AuthorizationService} 测试类
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
@Slf4j
@Import(H2DataSourceTestConfiguration.class)
@SpringBootTest(classes = { RedisAutoConfiguration.class, RedisOAuth2AuthorizationServiceConfiguration.class,
		RedisOAuth2AuthorizationService.class })
class RedisOAuth2AuthorizationServiceTests {

	@Autowired
	private RedisOAuth2AuthorizationService redisOAuth2AuthorizationService;

	private JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService;

	@Autowired
	public void setJdbcOAuth2AuthorizationService(DataSource dataSource) {
		JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
		// @formatter:off
		JdbcRegisteredClientRepository jdbcRegisteredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		this.jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, jdbcRegisteredClientRepository);
		// @formatter:on
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
	void save() {

	}

	@Test
	void remove() {

	}

	@Test
	void findById() throws JsonProcessingException {
		ObjectMapper objectMapper = ObjectMapperUtils.redis();
		OAuth2Authorization auth2Authorization = redisOAuth2AuthorizationService.findById(AUTHORIZATION_ID);
		log.info("根据 id：{} 查询Redis中的授权（不存在时从数据库中查询）：{}", ID, objectMapper.writeValueAsString(auth2Authorization));
	}

	@Test
	void findByToken() {

	}

}
