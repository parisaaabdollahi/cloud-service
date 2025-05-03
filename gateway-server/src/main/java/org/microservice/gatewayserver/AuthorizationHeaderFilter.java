package org.microservice.gatewayserver;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationHeaderFilter.class);

    @Autowired
    private Environment env;

    public AuthorizationHeaderFilter() {
        super(Config.class);
        logger.debug("AuthorizationHeaderFilter constructor called");
    }

    @Override
    public GatewayFilter apply(Config config) {
        logger.debug("AuthorizationHeaderFilter.apply() called");
        return (exchange, chain) -> {
            logger.debug("Filter chain execution started");
            ServerHttpRequest request = exchange.getRequest();
            logger.debug("Request path: {}", request.getPath());
            logger.debug("Request headers: {}", request.getHeaders());
            
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                logger.debug("No Authorization header found");
                return onError(exchange, "No Authorization header exists", HttpStatus.UNAUTHORIZED);
            }
            String authorizationHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
            logger.debug("Authorization header found: {}", authorizationHeader);
            String jwt = authorizationHeader.replace("Bearer", "");

            if (!isValidToken(jwt)) {
                logger.debug("Token validation failed");
                return onError(exchange, "Invalid JWT token", HttpStatus.UNAUTHORIZED);
            }
            logger.debug("Token validation successful");
            return chain.filter(exchange);
        };
    }

    public static class Config {
        // Add any configuration properties here if needed
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus status) {
        logger.debug("Error occurred: {}", err);
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    private boolean isValidToken(String jwt) {
        logger.debug("Validating token");
        boolean isValid = true;
        String subject = null;

        String tokenSecret = env.getProperty("token.secret");
        byte[] secretKeyBytes = Base64.getEncoder().encode(tokenSecret.getBytes());
        SecretKey signingKey = new SecretKeySpec(secretKeyBytes, SignatureAlgorithm.HS512.getJcaName());
        JwtParser jwtParser = Jwts.parserBuilder().setSigningKey(signingKey).build();

        try {
            Jwt<Header, Claims> parseToken = jwtParser.parse(jwt);
            subject = parseToken.getBody().getSubject();
            logger.debug("Token parsed successfully, subject: {}", subject);
        } catch (Exception e) {
            logger.error("Token validation failed with error: {}", e.getMessage());
            return false;
        }

        if (subject == null || subject.isEmpty()) {
            logger.debug("Token subject is null or empty");
            isValid = false;
        }
        return isValid;
    }
}
