package com.okta.createverifytokens;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Our simple class that demonstrates how to create and decode JWTs
 */
public class JWTDemo {

	private static final String SECRET_KEY;

	static {
		try {
			SECRET_KEY = Files
					.readAllLines(Paths.get(ClassLoader.getSystemResource("secret-key.dat").toURI()))
					.get(0);
		} catch (final IOException | URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}

	// Sample method to construct a JWT
	public static String createJWT(final String id, final String issuer, final String subject, final long ttlMillis) {

		// The JWT signature algorithm we will be using to sign the token
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

		final long nowMillis = System.currentTimeMillis();
		final Date now = new Date(nowMillis);

		// We will sign our JWT with our ApiKey secret
		final byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
		final Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

		// Let's set the JWT Claims
		final JwtBuilder builder = Jwts.builder().setId(id)
				.setIssuedAt(now)
				.setSubject(subject)
				.setIssuer(issuer)
				.signWith(signatureAlgorithm, signingKey);

		// if it has been specified, let's add the expiration
		if (ttlMillis >= 0) {
			final long expMillis = nowMillis + ttlMillis;
			final Date exp = new Date(expMillis);
			builder.setExpiration(exp);
		}

		// Builds the JWT and serializes it to a compact, URL-safe string
		return builder.compact();
	}

	public static Claims decodeJWT(final String jwt) {

		// This line will throw an exception if it is not a signed JWS (as expected)
		return Jwts.parser()
				.setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
				.parseClaimsJws(jwt).getBody();
	}

}
