package io.c6.jwt.playground;

import static java.text.MessageFormat.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

		final var jwtId = "e2f65951-6ff3-4792-932c-4ea8c27ba9e0";
		final var jwtIssuer = "Sample Issuer";
		final var jwtSubject = "Sample Subject";
		final var jwtAudience = "Sample Audience";
		final var jwtTimeToLive = 800000;

		final var jwt = AzureClientAssertionDemo.createJWT(
				jwtId, // claim = jti
				jwtIssuer, // claim = iss
				jwtSubject, // claim = sub
				jwtAudience, // claim = aud
				jwtTimeToLive // used to calculate expiration (claim = exp)
		);

		logger.info(format("jwt = \"{0}\"", jwt));

		final var claims = AzureClientAssertionDemo.decodeJWT(jwt);

		logger.info(format("claims = {0}", claims));

		assertEquals(jwtId, claims.getId());
		assertEquals(jwtIssuer, claims.getIssuer());
		assertEquals(jwtSubject, claims.getSubject());

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

		final var jwtId = "e2f65951-6ff3-4792-932c-4ea8c27ba9e0";
		final var jwtIssuer = "Sample Issuer";
		final var jwtSubject = "Sample Subject";
		final var jwtAudience = "Sample Audience";
		final var jwtTimeToLive = 800000;

		final var jwt = AzureClientAssertionDemo.createJWT(
				jwtId, // claim = jti
				jwtIssuer, // claim = iss
				jwtSubject, // claim = sub
				jwtAudience, // claim = aud
				jwtTimeToLive // used to calculate expiration (claim = exp)
		);

		logger.info(format("jwt = \"{0}\"", jwt));

		// tamper with the JWT
		final var stringBuilder = new StringBuilder(jwt);
		stringBuilder.setCharAt(22, 'I');
		final var tamperedJwt = stringBuilder.toString();

		logger.info(format("tamperedJwt = \"{0}\"", tamperedJwt));

		assertNotEquals(jwt, tamperedJwt);

		// this will fail with a SignatureException
		assertThrows(SignatureException.class, () -> AzureClientAssertionDemo.decodeJWT(tamperedJwt));

	}

}
