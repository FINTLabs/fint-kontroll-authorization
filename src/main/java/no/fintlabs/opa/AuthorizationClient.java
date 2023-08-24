package no.fintlabs.opa;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.util.AuthenticationUtil;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;

@Slf4j
@Component
public class AuthorizationClient {

    private final OpaApiClient opaApiClient;
    private final AuthenticationUtil authenticationUtil;

    public AuthorizationClient(OpaApiClient opaApiClient, AuthenticationUtil authenticationUtil) {
        this.opaApiClient = opaApiClient;
        this.authenticationUtil = authenticationUtil;
    }

    public Mono<Boolean> isAuthorized(String user, String operation) {
        return opaApiClient.hasUserAuthorization(user, operation);
    }

    public Mono<LinkedHashMap> getUserScopes() {
        return authenticationUtil.isAuthenticated()
                .flatMapMany(authenticated -> {
                    if (authenticated) {
                        log.info("User is authenticated, getting user scopes");
                        return lookupScopes();
                    } else {
                        log.info("User is not authenticated");
                        return Mono.empty();
                    }
                })
                .doOnError(throwable -> log.error("Error checking authentication", throwable))
                .singleOrEmpty();
    }

    private Mono<LinkedHashMap> lookupScopes() {
        return authenticationUtil.getUserName()
                .flatMap(userName -> {
                    log.info("Looking up scopes for user {}", userName);
                    return opaApiClient.getScopesForUser(userName);
                });
    }
}
