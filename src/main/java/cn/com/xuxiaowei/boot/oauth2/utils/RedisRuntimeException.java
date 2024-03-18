package cn.com.xuxiaowei.boot.oauth2.utils;

/**
 * Redis 异常
 *
 * @since 2.0.0
 * @author xuxiaowei
 */
public class RedisRuntimeException extends RuntimeException {

	public RedisRuntimeException(String message) {
		super(message);
	}

}
