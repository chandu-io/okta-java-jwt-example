package io.c6.jwt.playground;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;

public final class AzureJWTSigningKeyResolver extends SigningKeyResolverAdapter {

	private static final Logger logger = LogManager.getLogger();
	private static final HttpClient httpClient = HttpClient.newHttpClient();
	private static final ObjectMapper mapper = new ObjectMapper()
			.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
			.setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);

	private final String jwksUri;
	private final Duration timeout;

	public AzureJWTSigningKeyResolver(final String jwksUri, final Duration timeout) {
		this.jwksUri = jwksUri;
		this.timeout = timeout;
	}

	@Override
	public Key resolveSigningKey(final JwsHeader header, final Claims claims) {
		try {
			final var decodedKey = getJWKS(jwksUri, timeout) // TODO: cache this
					.map(JWKS::getKeys)
					.map(List::stream)
					.map(s -> s.filter(jwk -> jwk != null && jwk.getKid() != null))
					.map(s -> s.filter(jwk -> jwk.getKid().equals(header.get("kid"))))
					.flatMap(Stream::findFirst)
					.flatMap(jwk -> Optional.ofNullable(jwk.getX5c()))
					.map(List::stream)
					.flatMap(Stream::findFirst)
					.map(Base64::decodeBase64)
					.orElse(new byte[0]);
			if (decodedKey.length == 0) {
				return null;
			} else {
				final var factory = CertificateFactory.getInstance("X.509");
				final var certificate = factory.generateCertificate(new ByteArrayInputStream(decodedKey));
				return certificate.getPublicKey();
			}
		} catch (final Exception e) {
			logger.error(e);
			return null;
		}
	}

	public static Optional<JWKS> getJWKS(final String jwksUri, final Duration timeout) {
		try {
			final var endpoint = new URI(jwksUri);
			final var request = HttpRequest.newBuilder().uri(endpoint).GET().build();
			final var bodyHandler = HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8);
			final var content = httpClient.sendAsync(request, bodyHandler)
					.thenApply(HttpResponse::body)
					.get(timeout.toMinutes(), TimeUnit.MINUTES);
			return Optional.ofNullable(mapper.readValue(content, JWKS.class));
		} catch (final Exception e) {
			logger.error(e);
			return Optional.empty();
		}
	}

	/**
	 * Refer: <a href="https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-set-properties">JSON Web Key Set Properties</a>
	 */
	static final class JWK {
		private String alg;
		private String kty;
		private String use;
		private List<String> x5c;
		private String n;
		private String e;
		private String kid;
		private String x5t;

		public String getAlg() {
			return alg;
		}

		public String getKty() {
			return kty;
		}

		public String getUse() {
			return use;
		}

		public List<String> getX5c() {
			return x5c;
		}

		public String getN() {
			return n;
		}

		public String getE() {
			return e;
		}

		public String getKid() {
			return kid;
		}

		public String getX5t() {
			return x5t;
		}

		public void setAlg(final String alg) {
			this.alg = alg;
		}

		public void setKty(final String kty) {
			this.kty = kty;
		}

		public void setUse(final String use) {
			this.use = use;
		}

		public void setX5c(final List<String> x5c) {
			this.x5c = x5c;
		}

		public void setN(final String n) {
			this.n = n;
		}

		public void setE(final String e) {
			this.e = e;
		}

		public void setKid(final String kid) {
			this.kid = kid;
		}

		public void setX5t(final String x5t) {
			this.x5t = x5t;
		}

		@Override
		public String toString() {
			return new StringJoiner(", ", JWK.class.getSimpleName() + "[", "]")
					.add("alg='" + alg + "'")
					.add("kty='" + kty + "'")
					.add("use='" + use + "'")
					.add("x5c=" + x5c)
					.add("n='" + n + "'")
					.add("e='" + e + "'")
					.add("kid='" + kid + "'")
					.add("x5t='" + x5t + "'")
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
			final var jwk = (JWK) o;
			return Objects.equals(getAlg(), jwk.getAlg())
					&& Objects.equals(getKty(), jwk.getKty())
					&& Objects.equals(getUse(), jwk.getUse())
					&& Objects.equals(getX5c(), jwk.getX5c())
					&& Objects.equals(getN(), jwk.getN())
					&& Objects.equals(getE(), jwk.getE())
					&& Objects.equals(getKid(), jwk.getKid())
					&& Objects.equals(getX5t(), jwk.getX5t());
		}

		@Override
		public int hashCode() {
			return Objects.hash(getAlg(), getKty(), getUse(), getX5c(), getN(), getE(), getKid(), getX5t());
		}
	}

	/**
	 * Refer: <a href="https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-set-properties">JSON Web Key Set Properties</a>
	 */
	static final class JWKS {
		private List<JWK> keys;

		public List<JWK> getKeys() {
			return keys;
		}

		public void setKeys(final List<JWK> keys) {
			this.keys = keys;
		}

		@Override
		public String toString() {
			return new StringJoiner(", ", JWKS.class.getSimpleName() + "[", "]")
					.add("keys=" + keys)
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
			final var jwks = (JWKS) o;
			return Objects.equals(getKeys(), jwks.getKeys());
		}

		@Override
		public int hashCode() {
			return Objects.hash(getKeys());
		}
	}

}
