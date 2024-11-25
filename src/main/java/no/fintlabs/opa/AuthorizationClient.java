package no.fintlabs.opa;

import lombok.extern.slf4j.Slf4j;
import no.fintlabs.opa.model.AuthRole;
import no.fintlabs.opa.model.AuthorizedRole;
import no.fintlabs.opa.model.Scope;
import no.fintlabs.util.AuthenticationUtil;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

import static no.fintlabs.opa.model.AuthorizedRole.PORTAL_ADMIN;
import static no.fintlabs.opa.model.AuthorizedRole.RESSURS_ADMIN;
import static no.fintlabs.opa.model.AuthorizedRole.SYSTEM_ADMIN;
import static no.fintlabs.opa.model.AuthorizedRole.TJENESTE_ADMIN;

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
        return authenticationUtil.isAdmin() || getRoles().contains(SYSTEM_ADMIN.getShortName());
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
            return opaApiClient.getRolesForUser(userName, authenticationUtil.getUrl());
        } else {
            log.info("User is not authenticated");
            return List.of();
        }
    }

    public List<AuthRole> getUserRoles() {
        List<AuthRole> userRoles = new ArrayList<>();

        if (isAdmin()) {
            userRoles.add(AuthRole.builder()
                                  .name(PORTAL_ADMIN.getName())
                                  .id(PORTAL_ADMIN.getShortName())
                                  .build());
        }

        List<String> roles = getRoles();

        roles.forEach(role-> AuthorizedRole.getRoleByShortName(role)
                .ifPresent(r -> userRoles.add(AuthRole.builder()
                                                      .name(r.getName())
                                                      .id(r.getShortName())
                                                      .build())));

        return userRoles;
    }

    public boolean canManageAccessAssignment(String roleId) {
        List<String> roles = getRoles();

        if (isAdmin()) {
            return true;
        }

        boolean allowed = false;

        if (roles.contains(RESSURS_ADMIN.getShortName())) {
            if(AuthorizedRole.getValidAssignmentRolesForRessursAdmin().contains(roleId)) {
                allowed = true;
            }
        }

        if (roles.contains(TJENESTE_ADMIN.getShortName())) {
            if(AuthorizedRole.getValidAssignmentRolesForTjenesteAdmin().contains(roleId)) {
                allowed = true;
            }
        }

        return allowed;
    }

    public boolean canCreateAccessPermission() {
        return isAdmin();
    }

    public boolean canCreateFeature() {
        return isAdmin();
    }

    public boolean canDeleteAccessAssignment() {
        return isAdmin();
    }

    private List<Scope> lookupScopesList() {
        String userName = authenticationUtil.getUserName();
        log.info("Looking up scopes for user {}", userName);
        return opaApiClient.getScopesListForUser(userName, authenticationUtil.getUrl());
    }
}
