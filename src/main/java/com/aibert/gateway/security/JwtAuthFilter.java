package com.aibert.gateway.security;

import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final List<String> publicPaths = List.of("/api/auth/**");

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        boolean isPublic = publicPaths.stream()
                .anyMatch(p -> pathMatcher.match(p, path));

        if (isPublic) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        if (!jwtUtil.isTokenValid(token)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        Claims claims = jwtUtil.extractAllClaims(token);

        ServerWebExchange mutatedExchange = exchange.mutate()
                .request(r -> r
                        .header("X-User-Email", claims.getSubject())
                        .header("X-User-Id", claims.get("userId", String.class))
                        .header("X-User-Role", claims.get("role", String.class))
                        .header("X-Student-Id", claims.get("userId", String.class))
                        .header("studentId", claims.get("userId", String.class))
                )
                .build();

        return chain.filter(mutatedExchange);
    }

    @Override
    public int getOrder() {
        return -1;
    }
}