package com.okta.createverifytokens;

import static java.text.MessageFormat.format;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Test;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;

public class JWTDemoTest {

	private static final Logger logger = LogManager.getLogger();

	/**
	 * Create a simple JWT, decode it, and assert the claims
	 */
	@Test
	public void createAndDecodeJWT() {

		String jwtId = "SOMEID1234";
		String jwtIssuer = "JWT Demo";
		String jwtSubject = "Andrew";
		int jwtTimeToLive = 800000;

		String jwt = JWTDemo.createJWT(
				jwtId, // claim = jti
				jwtIssuer, // claim = iss
				jwtSubject, // claim = sub
				jwtTimeToLive // used to calculate expiration (claim = exp)
		);

		logger.info(format("jwt = \"{0}\"", jwt));

		Claims claims = JWTDemo.decodeJWT(jwt);

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

		String notAJwt = "This is not a JWT";

		// This will fail with expected exception listed above
		assertThrows(MalformedJwtException.class, () -> JWTDemo.decodeJWT(notAJwt));

	}

	/**
	 * Create a simple JWT, modify it, and try to decode it
	 */
	@Test
	public void createAndDecodeTamperedJWT() {

		String jwtId = "SOMEID1234";
		String jwtIssuer = "JWT Demo";
		String jwtSubject = "Andrew";
		int jwtTimeToLive = 800000;

		String jwt = JWTDemo.createJWT(
				jwtId, // claim = jti
				jwtIssuer, // claim = iss
				jwtSubject, // claim = sub
				jwtTimeToLive // used to calculate expiration (claim = exp)
		);

		logger.info(format("jwt = \"{0}\"", jwt));

		// tamper with the JWT

		StringBuilder stringBuilder = new StringBuilder(jwt);
		stringBuilder.setCharAt(22, 'I');

		String tamperedJwt = stringBuilder.toString();

		logger.info(format("tamperedJwt = \"{0}\"", tamperedJwt));

		assertNotEquals(jwt, tamperedJwt);

		// this will fail with a SignatureException

		assertThrows(SignatureException.class, () -> JWTDemo.decodeJWT(tamperedJwt));

	}

}
