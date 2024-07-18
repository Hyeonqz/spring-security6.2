package org.spring.securityjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.swagger.v3.core.jackson.ModelResolver;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;

@Configuration
public class SwaggerConfig {
	@Bean
	public ModelResolver modelResolver(ObjectMapper objectMapper){
		return new ModelResolver(objectMapper);
	}

	@Bean
	public OpenAPI openAPI() {
		Info info = new Info()
			.version("v1.0.0")
			.title("Security & JWT API")
			.description("SpringSecurity + JWT API 목록");

		return new OpenAPI().info(info);
	}
}
