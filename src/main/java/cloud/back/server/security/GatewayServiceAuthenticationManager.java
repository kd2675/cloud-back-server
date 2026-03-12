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
    private final Cache<String, Boolean> nonceCache = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(10))
            .maximumSize(100_000)
            .build();

    public GatewayServiceAuthenticationManager(GatewayServiceAuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof GatewayServiceAuthenticationToken token)) {
            return Mono.empty();
        }

        try {
            validateSecretConfigured();
            validateTimestamp(token.getTimestamp());
            validateNonce(token.getGatewayId(), token.getNonce());
            validateSignature(token);
            return Mono.just(GatewayServiceAuthenticationToken.authenticated(
                    token.getGatewayId(),
                    token.getHttpMethod(),
                    token.getRequestPath(),
                    token.getTimestamp(),
                    token.getNonce(),
                    token.getSignature()
            ));
        } catch (AuthenticationException ex) {
            return Mono.error(ex);
        } catch (Exception ex) {
            return Mono.error(new BadCredentialsException("Invalid gateway authentication", ex));
        }
    }

    private void validateSecretConfigured() {
        if (authProperties.getSharedSecret() == null || authProperties.getSharedSecret().isBlank()) {
            throw new BadCredentialsException("Gateway shared secret is not configured");
        }
    }

    private void validateTimestamp(String timestamp) {
        long requestEpochMillis;
        try {
            requestEpochMillis = Long.parseLong(timestamp);
        } catch (NumberFormatException ex) {
            throw new BadCredentialsException("Invalid gateway timestamp");
        }

        long skewMillis = authProperties.getAllowedClockSkewSeconds() * 1000L;
        long now = Instant.now().toEpochMilli();
        if (Math.abs(now - requestEpochMillis) > skewMillis) {
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
        String payload = buildPayload(
                token.getGatewayId(),
                token.getHttpMethod(),
                token.getRequestPath(),
                token.getTimestamp(),
                token.getNonce()
        );
        String expectedSignature = hmacHex(payload, authProperties.getSharedSecret());
        if (!MessageDigest.isEqual(
                expectedSignature.getBytes(StandardCharsets.UTF_8),
                token.getSignature().getBytes(StandardCharsets.UTF_8)
        )) {
            throw new BadCredentialsException("Gateway signature mismatch");
        }
    }

    public static String buildPayload(
            String gatewayId,
            String httpMethod,
            String requestPath,
            String timestamp,
            String nonce
    ) {
        return String.join("\n", gatewayId, httpMethod, requestPath, timestamp, nonce);
    }

    public static String hmacHex(String payload, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
    }
}
