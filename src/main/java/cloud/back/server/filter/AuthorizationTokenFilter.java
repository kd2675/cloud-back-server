//package cloud.back.server.filter;
//
//import io.jsonwebtoken.Jwts;
//import lombok.Getter;
//import lombok.RequiredArgsConstructor;
//import lombok.Setter;
//import lombok.extern.slf4j.Slf4j;
//import org.apache.logging.log4j.util.Strings;
//import org.example.core.response.base.vo.Code;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
//import org.springframework.http.HttpHeaders;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.stereotype.Component;
//import org.springframework.web.reactive.function.client.WebClient;
//
//@Slf4j
//@Component
//@RequiredArgsConstructor
//public class AuthorizationTokenFilter extends AbstractGatewayFilterFactory<AuthorizationTokenFilter.Config> {
//    @Value("${jwt.secret}")
//    private String secret;
//
//    private final WebClient webClient;
//
//    @Override
//    public GatewayFilter apply(Config config) {
//        return (exchange, chain) -> {
//            ServerHttpRequest request = exchange.getRequest();
//
//            // 헤더에 Authorization이 없을 경우 (토큰을 발급받지 않은 경우)
//            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION))
//                return OnError.onError(exchange, "No Authorization Header", Code.UNAUTHORIZED);
//
//            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
//            String token = authorizationHeader.replace("Bearer ", "");
//            // 토큰 검증 실패 시
//            if (isTokenValid(token))
//                return OnError.onError(exchange, "Token is not valid", Code.UNAUTHORIZED);
//
//            return chain.filter(exchange);
//
//        };
//    }
//    // 토큰 검증을 위한 메서드
//    private boolean isTokenValid(String token) {
//        String subject = null;
//
//        try {
//            subject = Jwts.parser()
//                    .setSigningKey(secret.getBytes())
//                    .parseClaimsJws(token)
//                    .getBody()
//                    .getSubject();
//
//        } catch (Exception e) {
//            log.warn("exception is occurred : {}", e.getMessage());
//        }
//
//        return !Strings.isBlank(subject);
//    }
//
//    @Getter
//    @Setter
//    public static class Config {
//    }
//
//}