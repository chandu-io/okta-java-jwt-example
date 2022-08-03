package io.c6.jwt.playground;

import static java.text.MessageFormat.format;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Our simple class that demonstrates how to create and decode JWTs
 */
public class AzureClientAssertionDemo {

	public static final List<String> AZURE_TOKEN_ENDPOINT_FMT_LIST = List.of(
			"https://login.windows.net/{0}/oauth2/token",
			"https://login.windows.net/{0}/oauth2/v2.0/token",
			"https://login.microsoftonline.com/{0}/oauth2/token",
			"https://login.microsoftonline.com/{0}/oauth2/v2.0/token"
	);
	private static final String RES_NAME = "base64-encoded-pfx-file-content.dat";
	// https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keystore-types
	private static final String PKCS12 = "pkcs12";
	private static final String FORM_BODY_KEY_SCOPE = "scope";
	private static final String FORM_BODY_KEY_CLIENT_ID = "client_id";
	private static final String FORM_BODY_KEY_CLIENT_ASSERTION_TYPE = "client_assertion_type";
	private static final String FORM_BODY_KEY_CLIENT_ASSERTION = "client_assertion";
	private static final String FORM_BODY_KEY_GRANT_TYPE = "grant_type";
	private static final String MGMT_SCOPE = "https://management.core.windows.net/.default";
	private static final String HEADER_KEY_CONTENT_TYPE = "Content-Type";
	private static final String JWT_BEARER_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
	private static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
	private static final String X_WWW_FORM_URLENCODED_CONTENT_TYPE = "application/x-www-form-urlencoded";
	private static final String V2 = "/v2.0";

	private static final HttpClient httpClient = HttpClient.newHttpClient();
	private static final ObjectMapper mapper = new ObjectMapper()
			.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
			.setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);

	private static final Key privateKey;
	private static final Certificate certificate;
	private static final String encodedThumbprint;

	static {
		final var password = "".toCharArray(); // TODO
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
		} catch (final Exception e) {
			e.printStackTrace(System.err);
			throw new RuntimeException(e);
		}
	}

	/**
	 * Sample method to construct a JWT token
	 *
	 * @param azureTokenEndpointFmt Azure token endpoint format string
	 * @param tenantId              tenant Id
	 * @param clientId              client Id
	 * @param assertionExpiration   assertion expiration
	 * @return JWT token
	 */
	public static String createJWT(
			final String azureTokenEndpointFmt,
			final String tenantId,
			final String clientId,
			final Duration assertionExpiration) {

		final var id = UUID.randomUUID().toString();
		final var audience = format(azureTokenEndpointFmt, tenantId);

		final var now = Instant.now();
		final var issuedAt = new Date(now.toEpochMilli());
		final var expiration = assertionExpiration.isNegative()
				? null
				: new Date(now.plus(assertionExpiration).toEpochMilli());

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
				.setExpiration(expiration)
				.setIssuer(clientId)
				.setId(id)
				.setNotBefore(issuedAt)
				.setSubject(clientId)
				.setIssuedAt(issuedAt)
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

		return Jwts.parser()
				.setSigningKey(privateKey)
				// This line will throw an exception if it is not a signed JWS (as expected)
				.parseClaimsJws(jwt)
				.getBody();
	}

	/**
	 * Sample method to get a token form Azure.
	 *
	 * @param azureTokenEndpointFmt Azure token endpoint format string
	 * @param tenantId              tenant Id
	 * @param clientId              client Id
	 * @param assertionExpiration   assertion expiration
	 * @return token wrapped in a CompletableFuture
	 */
	public static CompletableFuture<String> getToken(
			final String azureTokenEndpointFmt,
			final String tenantId,
			final String clientId,
			final Duration assertionExpiration) {
		try {

			final var clientAssertion = createJWT(azureTokenEndpointFmt, tenantId, clientId, assertionExpiration);

			// Debugging
			System.out.println(format("clientAssertion={0}\n", clientAssertion));

			final var endpoint = new URI(format(azureTokenEndpointFmt, tenantId));

			var body = Map.of(
					FORM_BODY_KEY_CLIENT_ID, clientId,
					FORM_BODY_KEY_CLIENT_ASSERTION_TYPE, JWT_BEARER_ASSERTION,
					FORM_BODY_KEY_CLIENT_ASSERTION, clientAssertion,
					FORM_BODY_KEY_GRANT_TYPE, CLIENT_CREDENTIALS_GRANT_TYPE
			);

			if (azureTokenEndpointFmt.contains(V2)) {
				body = new Hashtable<>(body);
				body.put(FORM_BODY_KEY_SCOPE, MGMT_SCOPE);
			}

			final var formBody = toFormBody(body);

			final var request = HttpRequest.newBuilder()
					.uri(endpoint)
					.header(HEADER_KEY_CONTENT_TYPE, X_WWW_FORM_URLENCODED_CONTENT_TYPE)
					.POST(HttpRequest.BodyPublishers.ofString(formBody, StandardCharsets.UTF_8))
					.build();

			return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
					.thenApply(HttpResponse::body)
					.thenApply(content -> unmarshall(content, AzureJWTResponse.class))
					// Debugging
					.thenApply(response -> {
						System.out.println(format("response={0}\n", response));
						return response;
					})
					.thenApply(AzureJWTResponse::getAccessToken);

		} catch (final Exception e) {
			throw new CompletionException(e);
		}
	}

	static String toFormBody(final Map<String, String> map) {
		return map.entrySet().stream()
				.map(e -> format("{0}={1}", e.getKey(), URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)))
				.collect(Collectors.joining("&"));
	}

	static <T> T unmarshall(final String content, final Class<T> cls) {
		try {
			return mapper.readValue(content, cls);
		} catch (final Exception e) {
			throw new RuntimeException(e);
		}
	}

	static final class AzureJWTResponse {
		private String tokenType;
		private String accessToken;
		private int expiresIn;
		private int extExpiresIn;

		public String getTokenType() {
			return tokenType;
		}

		public String getAccessToken() {
			return accessToken;
		}

		public int getExpiresIn() {
			return expiresIn;
		}

		public int getExtExpiresIn() {
			return extExpiresIn;
		}

		public void setTokenType(final String tokenType) {
			this.tokenType = tokenType;
		}

		public void setAccessToken(final String accessToken) {
			this.accessToken = accessToken;
		}

		public void setExpiresIn(final int expiresIn) {
			this.expiresIn = expiresIn;
		}

		public void setExtExpiresIn(final int extExpiresIn) {
			this.extExpiresIn = extExpiresIn;
		}

		@Override
		public String toString() {
			return new StringJoiner(", ", AzureJWTResponse.class.getSimpleName() + "[", "]")
					.add("tokenType='" + tokenType + "'")
					.add("accessToken='" + accessToken + "'")
					.add("expiresIn=" + expiresIn)
					.add("extExpiresIn=" + extExpiresIn)
					.toString();
		}

		@Override
		public boolean equals(final Object o) {
			if (this == o) {
				return true;
			}
			if (o == null || getClass() != o.getClass()) {
				return false;
			}
			final var that = (AzureJWTResponse) o;
			return getExpiresIn() == that.getExpiresIn()
					&& getExtExpiresIn() == that.getExtExpiresIn()
					&& Objects.equals(getTokenType(), that.getTokenType())
					&& Objects.equals(getAccessToken(), that.getAccessToken());
		}

		@Override
		public int hashCode() {
			return Objects.hash(getTokenType(), getAccessToken(), getExpiresIn(), getExtExpiresIn());
		}
	}

	public static void main(final String... args) {
		try {
			final var azureTokenEndpointFmt = AZURE_TOKEN_ENDPOINT_FMT_LIST.get(2);
			final var tenantId = "03d449a5-f799-4eae-9828-4dc378a03128";
			final var clientId = "672837ab-c9da-4602-95d7-553b87f3fc9b";
			final var expiration = Duration.ofMinutes(5);
			final var timeout = Duration.ofMinutes(2);
			final var token = getToken(azureTokenEndpointFmt, tenantId, clientId, expiration)
					.get(timeout.toMinutes(), TimeUnit.MINUTES);
			System.out.println(format("token={0}\n", token));

			final var endpoint = new URL(azureTokenEndpointFmt);
			final var jwksUri = format(
					"{0}://{1}{2}{3}/keys",
					endpoint.getProtocol(),
					endpoint.getHost(),
					"/common/discovery",
					azureTokenEndpointFmt.contains(V2) ? V2 : ""
			);
			System.out.println(format("jwksUri={0}\n", jwksUri));

			final var signingKeyResolver = new AzureJWTSigningKeyResolver(jwksUri, timeout);
			final var claims = Jwts.parser()
					.setSigningKeyResolver(signingKeyResolver)
					.parseClaimsJws(token)
					.getBody();
			System.out.println(format("claims={0}\n", claims));

		} catch (Exception e) {
			e.printStackTrace(System.err);
		}
	}
}
