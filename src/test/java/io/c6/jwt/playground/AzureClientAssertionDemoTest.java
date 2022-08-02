package io.c6.jwt.playground;

import static java.text.MessageFormat.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;

public class AzureClientAssertionDemoTest {

	private static final Logger logger = LogManager.getLogger();

	/**
	 * Create a simple JWT, decode it, and assert the claims
	 */
	@Test
	public void createAndDecodeJWT() {

		final var tenantId = "03d449a5-f799-4eae-9828-4dc378a03128";
		final var clientId = "672837ab-c9da-4602-95d7-553b87f3fc9b";
		final var ttlMillis = Duration.ofMinutes(5).toMillis();

		final var client_assertion = AzureClientAssertionDemo.createJWT(tenantId, clientId, ttlMillis);

		logger.info(format("client_assertion = \"{0}\"", client_assertion));

		final var claims = AzureClientAssertionDemo.decodeJWT(client_assertion);

		logger.info(format("claims = {0}", claims));

		assertEquals(format(AzureClientAssertionDemo.AZURE_TOKEN_ENDPOINT_FMT, tenantId), claims.getAudience());
		assertEquals(clientId, claims.getIssuer());
		assertEquals(clientId, claims.getSubject());

	}

	/**
	 * Attempt to decode a bogus JWT and expect an exception
	 */
	@Test
	public void decodeShouldFail() {

		final var notAJwt = "This is not a JWT";

		// This will fail with expected exception listed above
		assertThrows(MalformedJwtException.class, () -> AzureClientAssertionDemo.decodeJWT(notAJwt));

	}

	/**
	 * Create a simple JWT, modify it, and try to decode it
	 */
	@Test
	public void createAndDecodeTamperedJWT() {

		final var tenantId = "03d449a5-f799-4eae-9828-4dc378a03128";
		final var clientId = "672837ab-c9da-4602-95d7-553b87f3fc9b";
		final var ttlMillis = Duration.ofMinutes(5).toMillis();

		final var client_assertion = AzureClientAssertionDemo.createJWT(tenantId, clientId, ttlMillis);

		logger.info(format("client_assertion = \"{0}\"", client_assertion));

		// tamper with the JWT
		final var stringBuilder = new StringBuilder(client_assertion);
		stringBuilder.setCharAt(22, 'I');
		final var tampered_assertion = stringBuilder.toString();

		logger.info(format("tampered_assertion = \"{0}\"", tampered_assertion));

		assertNotEquals(client_assertion, tampered_assertion);

		// this will fail with a SignatureException
		assertThrows(SignatureException.class, () -> AzureClientAssertionDemo.decodeJWT(tampered_assertion));

	}

}
