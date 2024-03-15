package cn.com.xuxiaowei.boot.oauth2.deserializer;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.io.IOException;
import java.util.Map;

/**
 * {@link ClientAuthenticationMethod} 反序列化
 *
 * @author xuxiaowei
 * @since 2.0.0
 */
public class ClientAuthenticationMethodDeserializer extends StdDeserializer<ClientAuthenticationMethod> {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	public ClientAuthenticationMethodDeserializer() {
		super(ClientAuthenticationMethod.class);
	}

	@Override
	public ClientAuthenticationMethod deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JacksonException {
		Map<String, String> map = OBJECT_MAPPER.readValue(p, new TypeReference<Map<String, String>>() {
		});
		return new ClientAuthenticationMethod(map.values().stream().findFirst().orElse(null));
	}

}
