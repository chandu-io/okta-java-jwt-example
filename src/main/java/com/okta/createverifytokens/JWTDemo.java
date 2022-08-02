package com.okta.createverifytokens;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Our simple class that demonstrates how to create and decode JWTs
 */
public class JWTDemo {

	private static final String RES_NAME = "base64-encoded-cer-file-content.dat";

	private static final Logger logger = LogManager.getLogger();

	private static final Key secretKey;

	static {
		try {
			final var resourcePath = Paths.get(ClassLoader.getSystemResource(RES_NAME).toURI());
			final var encodedKey = Files.readAllLines(resourcePath).get(0);
			final var decodedKey = Base64.decodeBase64(encodedKey);
			secretKey = new SecretKeySpec(decodedKey, SignatureAlgorithm.HS256.getJcaName());
		} catch (final IOException | URISyntaxException e) {
			logger.error(e.getMessage(), e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Sample method to construct a JWT token
	 *
	 * @param id        claim jti
	 * @param issuer    claim iss
	 * @param subject   claim sub
	 * @param ttlMillis TTL millis
	 * @return JWT token
	 */
	public static String createJWT(final String id, final String issuer, final String subject, final long ttlMillis) {

		final var nowMillis = System.currentTimeMillis();
		final var now = new Date(nowMillis);
		final var exp = ttlMillis >= 0 ? new Date(nowMillis + ttlMillis) : null;

		return Jwts.builder()
				// Set the JWT Claims
				.setId(id)
				.setIssuedAt(now)
				.setExpiration(exp)
				.setSubject(subject)
				.setIssuer(issuer)
				// Sign with secret key
				.signWith(secretKey, SignatureAlgorithm.HS256)
				// Build the JWT and serializes it to a compact, URL-safe string
				.compact();
	}

	/**
	 * Sample method to decode a JWT token
	 *
	 * @param jwt token string
	 * @return decoded claims
	 */
	public static Claims decodeJWT(final String jwt) {

		return Jwts.parserBuilder()
				.setSigningKey(secretKey)
				.build()
				// This line will throw an exception if it is not a signed JWS (as expected)
				.parseClaimsJws(jwt)
				.getBody();
	}
}
