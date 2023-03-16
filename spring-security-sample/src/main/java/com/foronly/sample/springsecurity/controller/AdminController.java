package com.foronly.sample.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 *
 * </p>
 *
 * @author li_cang_long
 * @since 2023/3/15 1:54
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

	@GetMapping("/demo")
	public Map<String, Object> demo() {
		HashMap<String, Object> map = new HashMap<String, Object>();
		map.put("code", "1");
		map.put("type", "SUCCESS");
		map.put("message", "admin login");
		map.put("data", null);
		return map;

	}
}
