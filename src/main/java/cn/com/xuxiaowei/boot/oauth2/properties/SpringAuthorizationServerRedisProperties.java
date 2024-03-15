package cn.com.xuxiaowei.boot.oauth2.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * spring-authorization-server Redis 配置
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
@Data
@Component
@ConfigurationProperties(prefix = "spring.authorization-server.redis")
public class SpringAuthorizationServerRedisProperties {

	/**
	 * Redis key 前缀
	 */
	private String prefix = "spring-authorization-server";

	/**
	 * registered client Redis 超时时间，单位为秒
	 */
	private long registeredClientTimeout = 3000;

	/**
	 * authorization Redis 超时时间，单位为秒
	 */
	private long authorizationTimeout = 3000;

	/**
	 * authorization consent Redis 超时时间，单位为秒
	 */
	private long authorizationConsentTimeout = 3000;

}
