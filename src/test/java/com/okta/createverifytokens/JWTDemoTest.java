package com.okta.createverifytokens;

import static org.junit.jupiter.api.Assertions.*;

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

		logger.info("jwt = \"" + jwt.toString() + "\"");

		Claims claims = JWTDemo.decodeJWT(jwt);

		logger.info("claims = " + claims.toString());

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

		logger.info("jwt = \"" + jwt.toString() + "\"");

		// tamper with the JWT

		StringBuilder tamperedJwt = new StringBuilder(jwt);
		tamperedJwt.setCharAt(22, 'I');

		logger.info("tamperedJwt = \"" + tamperedJwt.toString() + "\"");

		assertNotEquals(jwt, tamperedJwt.toString());

		// this will fail with a SignatureException

		assertThrows(SignatureException.class, () -> JWTDemo.decodeJWT(tamperedJwt.toString()));

	}

}
