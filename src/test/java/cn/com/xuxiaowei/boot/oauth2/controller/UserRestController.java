package cn.com.xuxiaowei.boot.oauth2.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author xuxiaowei
 * @since 2.0.0
 */
@RestController
public class UserRestController {

	@RequestMapping(value = { "/", "/user/info" }, method = { RequestMethod.GET, RequestMethod.POST })
	public Map<String, String> index(HttpServletRequest request, HttpServletResponse response) {
		Map<String, String> map = new HashMap<>();
		map.put("title", "徐晓伟");
		return map;
	}

}
