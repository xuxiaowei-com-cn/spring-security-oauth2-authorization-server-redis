package cn.com.xuxiaowei.boot.oauth2.constant;

/**
 * Redis 常量
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
public class RedisConstants {

	/**
	 * Redis 版本
	 */
	public static final String REDIS_VERSION = "redis_version";

	/**
	 * Redis 支持 GETEX（getAndExpire、getAndPersist）方法的最低版本
	 * <p>
	 * Caused by: io.lettuce.core.RedisCommandExecutionException: ERR unknown command
	 * `GETEX`, with args beginning with: `RPex`, `EX`, `100`,
	 */
	public static final String GETEX_VERSION = "6.2.0";

	/**
	 * Redis 支持 GETDEL（getAndDelete）方法的最低版本
	 * <p>
	 * Caused by: io.lettuce.core.RedisCommandExecutionException: ERR unknown command
	 * `GETDEL`, with args beginning with: `QfMW`,
	 */
	public static final String GETDEL_VERSION = "6.2.0";

	public static final String SETTINGS = "settings";

	public static final String REGISTERED_CLIENT_ID = "registeredClientId";

	public static final String PRINCIPAL_NAME = "principalName";

	public static final String AUTHORITIES = "authorities";

	public static final String SCOPES= "scopes";

}
