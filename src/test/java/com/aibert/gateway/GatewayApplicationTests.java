package com.aibert.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {
		"jwt.secret=secretLocalParaDesarrolloMuyLargoMinimo32Chars",
		"security.public-paths=/api/auth/**"
})
class GatewayApplicationTests {

	@Test
	void contextLoads() {
	}
}