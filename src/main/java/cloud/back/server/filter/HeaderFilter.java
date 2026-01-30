//package cloud.back.server.filter;
//
//import lombok.Getter;
//import lombok.RequiredArgsConstructor;
//import lombok.Setter;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.stereotype.Component;
//
//@Slf4j
//@Component
//@RequiredArgsConstructor
//public class HeaderFilter extends AbstractGatewayFilterFactory<HeaderFilter.Config> {
//
//    @Value("${jwt.secret}")
//    private String secret;
//
//    @Override
//    public GatewayFilter apply(Config config) {
//        return (exchange, chain) -> {
//            ServerHttpRequest request = exchange.getRequest();
//
//            if (!request.getHeaders().containsHeader("Auth-header")) {
//                return OnError.onError(exchange, "No Header", HttpStatus.UNAUTHORIZED);
//            }
//
//            String authorizationHeader = request.getHeaders().get("Auth-header").get(0);
//
//            if (!"cloud".equals(authorizationHeader)) {
//                return OnError.onError(exchange, "Not Match Header", HttpStatus.UNAUTHORIZED);
//            }
//
//            return chain.filter(exchange);
//        };
//    }
//
//    @Getter
//    @Setter
//    public static class Config {}
//
//}