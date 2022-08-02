package com.okta.createverifytokens;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Our simple class that demonstrates how to create and decode JWTs
 */
public class JWTDemo {

	private static final String SECRET_KEY;

	static {
		try {
			final var resourcePath = Paths.get(ClassLoader.getSystemResource("secret-key.dat").toURI());
			SECRET_KEY = Files.readAllLines(resourcePath).get(0);
		} catch (final IOException | URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	private static byte[] getSecretKey() {
		return Base64.getDecoder().decode(SECRET_KEY);
	}

	/**
	 * Sample method to construct a JWT token
 	 * @param id claim jti
	 * @param issuer claim iss
	 * @param subject claim sub
	 * @param ttlMillis TTL millis
	 * @return JWT token
	 */
	public static String createJWT(final String id, final String issuer, final String subject, final long ttlMillis) {

		// The JWT signature algorithm we will be using to sign the token
		final var signatureAlgorithm = SignatureAlgorithm.HS256;

		// We will sign our JWT with our ApiKey secret
		final var signingKey = new SecretKeySpec(getSecretKey(), signatureAlgorithm.getJcaName());

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
				// Sign with key
				.signWith(signingKey, signatureAlgorithm)
				// Build the JWT and serializes it to a compact, URL-safe string
				.compact();
	}

	/**
	 * Sample method to decode a JWT token
	 * @param jwt token string
	 * @return decoded claims
	 */
	public static Claims decodeJWT(final String jwt) {

		return Jwts.parserBuilder()
				.setSigningKey(getSecretKey())
				.build()
				// This line will throw an exception if it is not a signed JWS (as expected)
				.parseClaimsJws(jwt)
				.getBody();
	}

}
