package no.fintlabs.opa;

import lombok.extern.slf4j.Slf4j;
import no.vigoiks.resourceserver.security.FintJwtEndUserPrincipal;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

@Slf4j
@Component
public class OpaClient {
    private final WebClient webClient;

    public OpaClient(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    public Mono<Boolean> isAuthorized(String user, String operation) {
        return hasUserAuthorization(user, operation);
    }

    public Mono<LinkedHashMap> getUserScopes() {
        return isAuthenticated()
                .flatMapMany(authenticated -> {
                    if (authenticated) {
                        log.info("User is authenticated, calling lookupscopes");
                        return lookupScopes();
                    } else {
                        log.info("User is not authenticated");
                        return Mono.empty();
                    }
                })
                .doOnNext(s -> log.info("User scopes: {}", s))
                .singleOrEmpty();
    }

    private Mono<LinkedHashMap> lookupScopes() {
        return getUserName()
                .flatMap(userName -> {
                    log.info("Looking up scopes for user {}", userName);
                    return scopes(userName)
                            .doOnNext(map -> log.info("Got scopes from OPA: {}", map));
                });
    }

    private static Mono<SecurityContext> getSecurityContextMono() {
        return ReactiveSecurityContextHolder.getContext();
    }

    private Mono<Boolean> isAuthenticated() {
        return getSecurityContextMono()
                .map(securityContext -> {
                    Authentication authentication = securityContext.getAuthentication();
                    return authentication.isAuthenticated();
                })
                .doOnNext(authenticated -> {
                    if (authenticated) {
                        log.info("User is authenticated");
                    } else {
                        log.info("User is not authenticated");
                    }
                })
                .doOnError(throwable -> log.error("Error checking authentication", throwable));
    }

    @NotNull
    private Mono<LinkedHashMap> scopes(String user) {
        log.info("Getting scopes for user {}", user);

        return webClient.post()
                .uri("/scopes")
                .bodyValue(createOpaRequestData(user, "GET"))
                .retrieve()
                .bodyToMono(LinkedHashMap.class)
                .map(map -> {
                    log.info("Got scopes from OPA: {}", map);
                    return map;
                })
                .log()
                .doOnError(throwable -> log.error("Error getting scopes from OPA", throwable))
                .onErrorResume(throwable -> Mono.just(new LinkedHashMap()));
    }

    private Mono<Boolean> hasUserAuthorization(String user, String operation) {
        return webClient.post()
                .uri("/allow")
                .bodyValue(createOpaRequestData(user, operation))
                .retrieve()
                .bodyToMono(OpaResponse.class)
                .map(opaResponse -> {
                    log.info("User {} got authorization response for operation {}: {}", user, operation, opaResponse.result());
                    return authorized(opaResponse);
                })
                .log()
                .doOnError(throwable -> log.error("Error checking authorization in OPA", throwable))
                .onErrorResume(throwable -> Mono.just(false));
    }

    private static boolean authorized(OpaResponse opaResponse) {
        return opaResponse.result() != null && opaResponse.result().equals("true");
    }

    private Mono<String> getUserName() {
        return getSecurityContextMono()
                .flatMap(securityContext -> {
                    Authentication authentication = securityContext.getAuthentication();
                    JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
                    Jwt principal = (Jwt) jwtToken.getPrincipal();
                    FintJwtEndUserPrincipal fintJwtEndUserPrincipal = FintJwtEndUserPrincipal.from(principal);
                    String userName = fintJwtEndUserPrincipal.getMail() != null ? fintJwtEndUserPrincipal.getMail() : "";
                    return Mono.just(userName);
                });
    }

    private static Map<String, Object> createOpaRequestData(String user, String operation) {
        return Map.of("input", new OpaRequest(user, operation));
    }

    private static Map<String, Object> createOpaRequestData(String user) {
        return Map.of("input", new OpaRequest(user));
    }

    record OpaRequest(String user, String operation) {
        public OpaRequest(String user) {
            this(user, null);
        }
    }

    protected record OpaResponse(String result) {
    }
}
