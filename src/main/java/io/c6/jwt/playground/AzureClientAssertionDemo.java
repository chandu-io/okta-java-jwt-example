package io.c6.jwt.playground;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Our simple class that demonstrates how to create and decode JWTs
 */
public class AzureClientAssertionDemo {

	private static final String RES_NAME = "base64-encoded-pfx-file-content.dat";

	// https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keystore-types
	private static final String PKCS12 = "pkcs12";

	private static final Logger logger = LogManager.getLogger();

	private static final Key privateKey;

	private static final Certificate certificate;

	private static final String encodedThumbprint;


	static {
		final var password = "".toCharArray();
		try {
			final var resourcePath = Paths.get(ClassLoader.getSystemResource(RES_NAME).toURI());
			final var encodedKey = Files.readAllLines(resourcePath).get(0);
			final var decodedKey = Base64.decodeBase64(encodedKey);
			final var keyStore = KeyStore.getInstance(PKCS12);
			final var inputStream = new ByteArrayInputStream(decodedKey);
			keyStore.load(inputStream, password);
			final var alias = Collections.list(keyStore.aliases()).get(0);
			privateKey = keyStore.getKey(alias, password);
			certificate = keyStore.getCertificate(alias);
			final var thumbprint = DigestUtils.sha1Hex(certificate.getEncoded());
			encodedThumbprint = Base64.encodeBase64String(Hex.decodeHex(thumbprint));
		} catch (final IOException | URISyntaxException | CertificateException | KeyStoreException |
		               NoSuchAlgorithmException | UnrecoverableKeyException | DecoderException e) {
			logger.error(e.getMessage(), e);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Sample method to construct a JWT token
	 *
	 * @param id     claim jti
	 * @param issuer    claim iss
	 * @param subject   claim sub
	 * @param ttlMillis TTL millis
	 * @return JWT token
	 */
	public static String createJWT(
			final String id,
			final String issuer,
			final String subject,
			final String audience,
			final long ttlMillis) {

		final var nowMillis = System.currentTimeMillis();
		final var now = new Date(nowMillis);
		final var exp = ttlMillis >= 0 ? new Date(nowMillis + ttlMillis) : null;

		// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials#header
		final Map<String, Object> header = Map.of(
				JwsHeader.ALGORITHM, SignatureAlgorithm.RS256.name(),
				JwsHeader.TYPE, JwsHeader.JWT_TYPE,
				JwsHeader.X509_CERT_SHA1_THUMBPRINT, encodedThumbprint
		);

		// https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials#claims-payload
		return Jwts.builder()
				// Set the JWT Headers
				.setHeader(header)
				// Set the JWT Claims
				.setAudience(audience)
				.setExpiration(exp)
				.setIssuer(issuer)
				.setId(id)
				.setNotBefore(now)
				.setSubject(subject)
				.setIssuedAt(now)
				// Sign with private key
				.signWith(privateKey, SignatureAlgorithm.RS256)
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
				.setSigningKey(privateKey)
				.build()
				// This line will throw an exception if it is not a signed JWS (as expected)
				.parseClaimsJws(jwt)
				.getBody();
	}
}
