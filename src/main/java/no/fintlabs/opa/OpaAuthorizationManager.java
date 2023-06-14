package no.fintlabs.opa;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.vigoiks.resourceserver.security.FintJwtEndUserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
@Component
public class OpaAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    @Autowired
    private OpaClient opaClient;

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, AuthorizationContext context) {
        return authentication
                .map(a -> {
                    // Get the principal name from the JWT token
                    JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) a;
                    Jwt principal = (Jwt) jwtToken.getPrincipal();
                    FintJwtEndUserPrincipal from = FintJwtEndUserPrincipal.from(principal);

                    String principalName = (String) principal.getClaims().get("principalName");
                    log.info("Fant brukernavn {}", principalName);

                    ServerHttpRequest request = context.getExchange().getRequest();
                    log.info("Request method {}", request.getMethod());
                    log.info("Request path {}", request.getPath());

                    boolean authenticated = a.isAuthenticated();
                    log.info("Authenticated {}", authenticated);

                    // Kall til OPA, sjekk om brukeren har tilgang
                    boolean authorized = opaClient.isAuthorized(principalName, request.getMethodValue());

                    log.info("Authorized {}", authorized);
                    return new AuthorizationDecision(authorized);
                })
                .defaultIfEmpty(new AuthorizationDecision(false))
                .doOnError(error -> System.out.println("An error occured while authorizing: " + error.getMessage()));
    }

    @Override
    public Mono<Void> verify(Mono<Authentication> authentication, AuthorizationContext object) {
        System.out.println("OpaAuthorizationManager.verify");
        return ReactiveAuthorizationManager.super.verify(authentication, object);
    }
}
