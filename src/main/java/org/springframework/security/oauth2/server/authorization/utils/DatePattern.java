package org.springframework.security.oauth2.server.authorization.utils;

/*-
 * #%L
 * spring-security-oauth2-authorization-server-redis
 * %%
 * Copyright (C) 2022 - 2023 徐晓伟工作室
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

/**
 * 日期格式化类，提供常用的日期格式化对象
 *
 * @author xuxiaowei
 * @since 0.0.1
 */
public class DatePattern {

	/**
	 * 标准时间格式：HH:mm:ss
	 */
	public static final String NORM_TIME_PATTERN = "HH:mm:ss";

	/**
	 * 标准日期格式：yyyy-MM-dd
	 */
	public static final String NORM_DATE_PATTERN = "yyyy-MM-dd";

	/**
	 * 标准日期时间格式，精确到秒：yyyy-MM-dd HH:mm:ss
	 */
	public static final String NORM_DATETIME_PATTERN = "yyyy-MM-dd HH:mm:ss";

}
