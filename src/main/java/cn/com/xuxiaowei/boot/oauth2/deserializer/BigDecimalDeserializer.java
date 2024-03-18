package cn.com.xuxiaowei.boot.oauth2.deserializer;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;

/**
 * @author xuxiaowei
 * @since 2.0.0
 */
public class BigDecimalDeserializer extends JsonDeserializer<BigDecimal> {

	private static final int SCALE = 9;

	private static final RoundingMode ROUNDING_MODE = RoundingMode.HALF_UP;

	@Override
	public BigDecimal deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
		return new BigDecimal(p.getValueAsString()).setScale(SCALE, ROUNDING_MODE);
	}

}
