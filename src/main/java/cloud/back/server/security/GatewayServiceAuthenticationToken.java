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
    private final String contentSha256;
    private final String actualContentSha256;
    private final String signature;

    public GatewayServiceAuthenticationToken(
            String gatewayId,
            String httpMethod,
            String requestPath,
            String timestamp,
            String nonce,
            String contentSha256,
            String actualContentSha256,
            String signature
    ) {
        super(List.of());
        this.gatewayId = gatewayId;
        this.httpMethod = httpMethod;
        this.requestPath = requestPath;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.contentSha256 = contentSha256;
        this.actualContentSha256 = actualContentSha256;
        this.signature = signature;
        setAuthenticated(false);
    }

    private GatewayServiceAuthenticationToken(
            String gatewayId,
            String httpMethod,
            String requestPath,
            String timestamp,
            String nonce,
            String contentSha256,
            String actualContentSha256,
            String signature,
            boolean authenticated
    ) {
        super(List.of(new SimpleGrantedAuthority("ROLE_GATEWAY")));
        this.gatewayId = gatewayId;
        this.httpMethod = httpMethod;
        this.requestPath = requestPath;
        this.timestamp = timestamp;
        this.nonce = nonce;
        this.contentSha256 = contentSha256;
        this.actualContentSha256 = actualContentSha256;
        this.signature = signature;
        setAuthenticated(authenticated);
    }

    public static GatewayServiceAuthenticationToken authenticated(
            String gatewayId,
            String httpMethod,
            String requestPath,
            String timestamp,
            String nonce,
            String contentSha256,
            String actualContentSha256,
            String signature
    ) {
        return new GatewayServiceAuthenticationToken(
                gatewayId,
                httpMethod,
                requestPath,
                timestamp,
                nonce,
                contentSha256,
                actualContentSha256,
                signature,
                true
        );
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

    public String getContentSha256() {
        return contentSha256;
    }

    public String getActualContentSha256() {
        return actualContentSha256;
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
