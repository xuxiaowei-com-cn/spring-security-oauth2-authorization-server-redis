package org.springframework.security.crypto.password;

import lombok.Getter;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;

/**
 * @author xuxiaowei
 * @since 0.0.1
 */
public class PasswordUtils implements PasswordEncoder {

	private final Digester digester;

	public PasswordUtils(Algorithm algorithm) {
		this.digester = new Digester(algorithm.getValue(), 1);
	}

	@Override
	public String encode(CharSequence rawPassword) {
		byte[] digest = this.digester.digest(Utf8.encode(rawPassword));
		return encode(digest);
	}

	private String encode(byte[] digest) {
		return new String(Hex.encode(digest));
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		String rawPasswordEncoded = digest(rawPassword);
		return PasswordEncoderUtils.equals(encodedPassword, rawPasswordEncoded);
	}

	private String digest(CharSequence rawPassword) {
		byte[] digest = this.digester.digest(Utf8.encode(rawPassword));
		return encode(digest);
	}

	/**
	 * @author xuxiaowei
	 * @since 0.0.1
	 */
	@Getter
	public enum Algorithm {

		MD5("MD5"),

		SHA_1("SHA-1"),

		SHA_256("SHA-256");

		private final String value;

		Algorithm(String value) {
			this.value = value;
		}

	}

}
