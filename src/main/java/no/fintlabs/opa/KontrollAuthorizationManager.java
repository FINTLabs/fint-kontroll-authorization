package no.fintlabs.opa;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.vigoiks.resourceserver.security.FintJwtEndUserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

@Slf4j
@RequiredArgsConstructor
@Component
public final class KontrollAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    @Autowired
    private AuthorizationClient authorizationClient;

    @Value("${fint.kontroll.authorization.authorized-role:rolle}")
    private String authorizedRole;

    @Value("${fint.kontroll.authorization.authorized-admin-role:admin}")
    private String adminRole;

    @Value("${fint.kontroll.authorization.authorized-org-id:vigo.no}")
    private String authorizedOrgId;

    @Value("${fint.relations.default-base-url:localhost}")
    private String baseUrl;

    @Override
    public AuthorizationDecision check(Supplier<Authentication> auth, RequestAuthorizationContext requestContext) {

        if(getRequestPath(requestContext).contains("/swagger-ui") || getRequestPath(requestContext).contains("/api-docs")) {
            log.debug("Swagger or api-docs, skipping authorization");
            return new AuthorizationDecision(true);
        }

        Authentication authentication = auth.get();
        if (!(authentication instanceof final JwtAuthenticationToken jwtToken)) {
            log.warn("Illegal jwt token: " + authentication.getClass().getName());
            throw new AccessDeniedException("Access denied, illegal JwtAuthenticationToken: " + authentication.getClass().getName());
        }

        if (hasAdminRole(jwtToken)) {
            log.info("User has admin role, access granted");
            return new AuthorizationDecision(true);
        }

        if (!hasAdminRole(jwtToken) && !hasRoleAndAuthority(jwtToken)) {
            log.warn("Access denied, not correct role or org");
            throw new AccessDeniedException("Access is denied. Not correct org or role");
        }

        String userName = getUserNameFromToken(jwtToken);

        boolean authenticated = authentication.isAuthenticated();
        log.info("User {} got authentication result {}", userName, authenticated);

        boolean authorized = authorizationClient.isAuthorized(userName, getRequestMethod(requestContext));

        if (!authorized) {
            log.info("User not authorized, access denied");
            throw new AccessDeniedException("User not authorized, access is denied");
        }

        return new AuthorizationDecision(true);
    }

    private static String getRequestMethod(RequestAuthorizationContext sra) {
        log.debug("Request method {}", sra.getRequest().getMethod());
        log.debug("Request path {}", sra.getRequest().getRequestURI());
        return sra.getRequest().getMethod();
    }

    private static String getRequestPath(RequestAuthorizationContext sra) {
        log.debug("Request path {}", sra.getRequest().getRequestURI());
        return sra.getRequest().getRequestURI();
    }

    private String getUserNameFromToken(JwtAuthenticationToken jwtToken) {
        Jwt principal = (Jwt) jwtToken.getPrincipal();
        FintJwtEndUserPrincipal fintJwtEndUserPrincipal = FintJwtEndUserPrincipal.from(principal);
        return fintJwtEndUserPrincipal.getMail() != null ? fintJwtEndUserPrincipal.getMail() : "";
    }

    private boolean hasRoleAndAuthority(JwtAuthenticationToken jwtToken) {
        boolean hasRole = jwtToken.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + authorizedRole));
        boolean hasAuthority = jwtToken.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ORGID_" + authorizedOrgId));

//        return hasRole && hasAuthority;
        // TODO: Enable when viken is active
        return true;
    }

    private boolean hasAdminRole(JwtAuthenticationToken jwtToken) {
        log.info("Auth: Found base url: {}", baseUrl);
        log.info("Auth: Found admin role: {}", adminRole);

        boolean hasAdminRole = jwtToken.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + adminRole));

        return hasRoleAndAuthority(jwtToken) && hasAdminRole;
    }

    protected void setAuthorizedRole(String authorizedRole) {
        this.authorizedRole = authorizedRole;
    }

    protected void setAuthorizedOrgId(String authorizedOrgId) {
        this.authorizedOrgId = authorizedOrgId;
    }
}
