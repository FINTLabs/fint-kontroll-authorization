package no.fintlabs.opa;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.util.AuthenticationUtil;
import org.springframework.stereotype.Component;

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

    public Boolean isAuthorized(String user, String operation) {
        log.info("Checking if user {} is authorized for operation {}", user, operation);
        return opaApiClient.hasUserAuthorization(user, operation);
    }

    public LinkedHashMap getUserScopes() {
        log.info("Getting user scopes");
        Boolean authenticated = authenticationUtil.isAuthenticated();
        log.info("User is authenticated: {}", authenticated);

        if (authenticated) {
            log.info("User is authenticated, getting user scopes");
            return lookupScopes();
        } else {
            log.info("User is not authenticated");
            return new LinkedHashMap();
        }
    }

    private LinkedHashMap lookupScopes() {
        String userName = authenticationUtil.getUserName();
        log.info("Looking up scopes for user {}", userName);
        return opaApiClient.getScopesForUser(userName);
    }
}
