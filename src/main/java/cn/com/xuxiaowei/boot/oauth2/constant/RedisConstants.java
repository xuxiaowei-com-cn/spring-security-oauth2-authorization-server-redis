package cn.com.xuxiaowei.boot.oauth2.constant;

/**
 * Redis 常量
 *
 * @author xuxiaowei
 * @since 2.0.0
 * @see org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
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

	public static final String SCOPES = "scopes";

	public static final String ID = "id";

	public static final String AUTHORIZATION_GRANT_TYPE = "authorizationGrantType";

	public static final String AUTHORIZED_SCOPES = "authorizedScopes";

	public static final String ACCESS_TOKEN = "accessToken";

	public static final String REFRESH_TOKEN = "refreshToken";

	public static final String CLIENT_ID = "clientId";

	public static final String REDIRECT_URI = "redirectUri";

	public static final String AUTHORIZATION_REQUEST_URI = "authorizationRequestUri";

	public static final String AUTHORIZATION_URI = "authorizationUri";

	public static final String ATTRIBUTES = "attributes";

	public static final String ID_TOKEN = "id_token";

}
