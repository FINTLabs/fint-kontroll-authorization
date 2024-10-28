package no.fintlabs.opa;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.opa.model.Scope;
import no.fintlabs.util.AuthenticationUtil;
import org.springframework.stereotype.Component;

import java.util.List;

@Slf4j
@Component
public class AuthorizationClient {
    private final OpaApiClient opaApiClient;
    private final AuthenticationUtil authenticationUtil;

    public AuthorizationClient(OpaApiClient opaApiClient, AuthenticationUtil authenticationUtil) {
        this.opaApiClient = opaApiClient;
        this.authenticationUtil = authenticationUtil;
    }

    public Boolean isAuthorized(String user, String operation, String url) {
        log.info("Checking if user {} is authorized for operation {} on url {}", user, operation, url);
        return opaApiClient.hasUserAuthorization(user, operation, url);
    }

    public List<Scope> getUserScopesList() {
        log.info("Getting list of user scopes");
        Boolean authenticated = authenticationUtil.isAuthenticated();
        log.info("User is authenticated: {}", authenticated);

        if (authenticated) {
            log.info("User is authenticated, getting user scopes");
            return lookupScopesList();
        } else {
            log.info("User is not authenticated");
            return List.of();
        }
    }

    public boolean isAdmin() {
        return authenticationUtil.isAdmin();
    }

    public List<String> getRoles() {
        log.info("Getting list of roles");
        Boolean authenticated = authenticationUtil.isAuthenticated();
        log.info("User is authenticated: {}", authenticated);

        if (authenticated) {
            String userName = authenticationUtil.getUserName();

            if(userName == null || userName.isEmpty()) {
                log.info("Username not found in authorization token {}", userName);
                return List.of();
            }

            log.info("Looking up roles for user {}", userName);
            return opaApiClient.getRolesForUser(userName);
        } else {
            log.info("User is not authenticated");
            return List.of();
        }
    }

    private List<Scope> lookupScopesList() {
        String userName = authenticationUtil.getUserName();
        log.info("Looking up scopes for user {}", userName);
        return opaApiClient.getScopesListForUser(userName, authenticationUtil.getUrl());
    }
}
