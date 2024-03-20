package cn.com.xuxiaowei.boot.oauth2.utils;

import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.Map;

/**
 * @author xuxiaowei
 * @since 0.0.1
 */
public class OAuth2Utils {

	/**
	 * 解密 JWT Token，获取有效负载
	 * @param tokenValue Token
	 * @return 返回 有效负载
	 */
	public static Map<String, Object> payload(String tokenValue) throws ParseException {
		SignedJWT signedJWT = SignedJWT.parse(tokenValue);
		return signedJWT.getPayload().toJSONObject();
	}

}
