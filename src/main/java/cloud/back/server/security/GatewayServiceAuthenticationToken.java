package cloud.back.server.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

public class GatewayServiceAuthenticationToken extends AbstractAuthenticationToken {
    private final String gatewayId;
    private final String httpMethod;
    private final String requestPath;
    private final String timestamp;
    private final String nonce;
    private final String signature;

    public GatewayServiceAuthenticationToken(
            String gatewayId,
            String httpMethod,
            String requestPath,
            String timestamp,
            String nonce,
            String signature
    ) {
        super(List.of());
        this.gatewayId = gatewayId;
        this.httpMethod = httpMethod;
        this.requestPath = requestPath;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.signature = signature;
        setAuthenticated(false);
    }

    private GatewayServiceAuthenticationToken(
            String gatewayId,
            String httpMethod,
            String requestPath,
            String timestamp,
            String nonce,
            String signature,
            boolean authenticated
    ) {
        super(List.of(new SimpleGrantedAuthority("ROLE_GATEWAY")));
        this.gatewayId = gatewayId;
        this.httpMethod = httpMethod;
        this.requestPath = requestPath;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.signature = signature;
        setAuthenticated(authenticated);
    }

    public static GatewayServiceAuthenticationToken authenticated(
            String gatewayId,
            String httpMethod,
            String requestPath,
            String timestamp,
            String nonce,
            String signature
    ) {
        return new GatewayServiceAuthenticationToken(gatewayId, httpMethod, requestPath, timestamp, nonce, signature, true);
    }

    public String getGatewayId() {
        return gatewayId;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getRequestPath() {
        return requestPath;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getNonce() {
        return nonce;
    }

    public String getSignature() {
        return signature;
    }

    @Override
    public Object getCredentials() {
        return signature;
    }

    @Override
    public Object getPrincipal() {
        return gatewayId;
    }
}
