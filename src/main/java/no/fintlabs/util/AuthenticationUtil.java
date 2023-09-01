package no.fintlabs.util;

import lombok.extern.slf4j.Slf4j;
import no.vigoiks.resourceserver.security.FintJwtEndUserPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class AuthenticationUtil {
    public Mono<String> getUserName() {
        log.info("Getting user name");

        return getSecurityContextMono()
                .doOnNext(securityContext -> log.info("Got security context {}", securityContext))
                .flatMap(securityContext -> {
                    Authentication authentication = securityContext.getAuthentication();
                    JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
                    Jwt principal = (Jwt) jwtToken.getPrincipal();
                    FintJwtEndUserPrincipal fintJwtEndUserPrincipal = FintJwtEndUserPrincipal.from(principal);
                    String userName = fintJwtEndUserPrincipal.getMail() != null ? fintJwtEndUserPrincipal.getMail() : "";
                    return Mono.just(userName);
                });
    }

    public Mono<Boolean> isAuthenticated() {
        log.info("Checking if user is authenticated");

        return getSecurityContextMono()
                .doOnNext(securityContext -> log.info("Got security context {}", securityContext))
                .map(securityContext -> {
                    Authentication authentication = securityContext.getAuthentication();
                    return authentication.isAuthenticated();
                });
    }

    private Mono<SecurityContext> getSecurityContextMono() {
        return ReactiveSecurityContextHolder.getContext();
    }
}
