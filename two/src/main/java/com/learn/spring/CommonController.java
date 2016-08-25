package com.learn.spring;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

@Controller
@EnableWebMvc
public class CommonController {

	@RequestMapping(value = "/status", method = RequestMethod.GET)
	public @ResponseBody String getHealthCheck() {
		return "ok";
	}

}
