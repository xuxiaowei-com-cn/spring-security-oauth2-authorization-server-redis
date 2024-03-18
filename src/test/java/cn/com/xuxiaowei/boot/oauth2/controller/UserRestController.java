package cn.com.xuxiaowei.boot.oauth2.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * 仅用于自动化测试登陆完成时测试
 *
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
