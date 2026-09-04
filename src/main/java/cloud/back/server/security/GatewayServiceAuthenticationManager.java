package cloud.back.server.security;

import cloud.back.server.config.GatewayServiceAuthProperties;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;

@Component
public class GatewayServiceAuthenticationManager implements ReactiveAuthenticationManager {
    private final GatewayServiceAuthProperties authProperties;
    private final Cache<String, Boolean> nonceCache;

    public GatewayServiceAuthenticationManager(GatewayServiceAuthProperties authProperties) {
        this.authProperties = authProperties;
        long allowedClockSkewSeconds = authProperties.getAllowedClockSkewSeconds();
        if (allowedClockSkewSeconds < 0 || allowedClockSkewSeconds > Long.MAX_VALUE / 2) {
            throw new IllegalArgumentException("Gateway clock skew must be between 0 and " + Long.MAX_VALUE / 2);
        }
        this.nonceCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofSeconds(Math.max(1, allowedClockSkewSeconds * 2)))
                .maximumSize(100_000)
                .build();
    }

    /** timestamp, body hash, HMAC, nonce 순으로 검증하고 성공한 gatewayId만 인증 주체로 확정한다. */
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof GatewayServiceAuthenticationToken token)) {
            return Mono.empty();
        }

        try {
            validateTimestamp(token.getTimestamp());
            if (GatewayRequestBodyHashFilter.requiresBodyHash(token.getRequestPath())) {
                validateContentHash(token);
            }
            validateSignature(token);
            validateNonce(token.getGatewayId(), token.getNonce());
            return Mono.just(GatewayServiceAuthenticationToken.authenticated(
                    token.getGatewayId(),
                    token.getHttpMethod(),
                    token.getRequestPath(),
                    token.getTimestamp(),
                    token.getNonce(),
                    token.getContentSha256(),
                    token.getActualContentSha256(),
                    token.getSignature()
            ));
        } catch (AuthenticationException ex) {
            return Mono.error(ex);
        } catch (Exception ex) {
            return Mono.error(new BadCredentialsException("Invalid gateway authentication", ex));
        }
    }

    private void validateTimestamp(String timestamp) {
        long requestEpochMillis;
        try {
            requestEpochMillis = Long.parseLong(timestamp);
        } catch (NumberFormatException ex) {
            throw new BadCredentialsException("Invalid gateway timestamp");
        }

        Duration allowedSkew = Duration.ofSeconds(authProperties.getAllowedClockSkewSeconds());
        Duration actualSkew = Duration.between(Instant.ofEpochMilli(requestEpochMillis), Instant.now()).abs();
        if (actualSkew.compareTo(allowedSkew) > 0) {
            throw new BadCredentialsException("Gateway timestamp expired");
        }
    }

    private void validateNonce(String gatewayId, String nonce) {
        String key = gatewayId + ":" + nonce;
        Boolean previous = nonceCache.asMap().putIfAbsent(key, Boolean.TRUE);
        if (previous != null) {
            throw new BadCredentialsException("Gateway nonce already used");
        }
    }

    private void validateSignature(GatewayServiceAuthenticationToken token) throws Exception {
        String payload = GatewayRequestBodyHashFilter.requiresBodyHash(token.getRequestPath())
                ? buildPayload(
                        token.getGatewayId(),
                        token.getHttpMethod(),
                        token.getRequestPath(),
                        token.getTimestamp(),
                        token.getNonce(),
                        token.getContentSha256()
                )
                : buildPayload(
                        token.getGatewayId(),
                        token.getHttpMethod(),
                        token.getRequestPath(),
                        token.getTimestamp(),
                        token.getNonce()
                );
        String secret = authProperties.resolveSecret(token.getGatewayId());
        if (secret == null || secret.isBlank()) {
            throw new BadCredentialsException("Gateway secret is not configured for gatewayId");
        }
        String expectedSignature = hmacHex(payload, secret);
        if (!MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                token.getSignature().getBytes(StandardCharsets.UTF_8)
        )) {
            throw new BadCredentialsException("Gateway signature mismatch");
        }
    }

    /** body가 없는 호환 경로의 canonical HMAC payload를 만든다. */
    public static String buildPayload(
            String gatewayId,
            String httpMethod,
            String requestPath,
            String timestamp,
            String nonce
    ) {
        return String.join("\n", gatewayId, httpMethod, requestPath, timestamp, nonce);
    }

    /** body SHA-256까지 결속한 ZeroQ gateway canonical HMAC payload를 만든다. */
    public static String buildPayload(
            String gatewayId,
            String httpMethod,
            String requestPath,
            String timestamp,
            String nonce,
            String contentSha256
    ) {
        return String.join("\n", gatewayId, httpMethod, requestPath, timestamp, nonce, contentSha256);
    }

    private void validateContentHash(GatewayServiceAuthenticationToken token) {
        if (token.getContentSha256() == null || token.getActualContentSha256() == null) {
            throw new BadCredentialsException("Gateway request body hash is required");
        }
        if (!MessageDigest.isEqual(
                token.getContentSha256().getBytes(StandardCharsets.UTF_8),
                token.getActualContentSha256().getBytes(StandardCharsets.UTF_8)
        )) {
            throw new BadCredentialsException("Gateway request body hash mismatch");
        }
    }

    public static String hmacHex(String payload, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
    }
}
