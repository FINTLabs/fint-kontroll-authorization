package no.fintlabs.opa;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.fintlabs.util.AuthenticationUtil;
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

import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;

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

    @Autowired
    private AuthenticationUtil authenticationUtil;

    @Override
    public AuthorizationDecision check(Supplier<Authentication> auth, RequestAuthorizationContext requestContext) {
        log.debug("Checking authorization. Request URI: {}", getRequestPath(requestContext));

        if (getRequestPath(requestContext).contains("/swagger-ui") || getRequestPath(requestContext).contains("/api-docs") ||
            getRequestPath(requestContext).contains("/opabundle") || getRequestPath(requestContext).contains("/actuator") || getRequestPath(requestContext).contains("/metrics")) {
            log.debug("Swagger or api-docs, skipping authorization");
            return new AuthorizationDecision(true);
        }

        Authentication authentication = auth.get();
        if (!(authentication instanceof final JwtAuthenticationToken jwtToken)) {
            logInvalidTokenRequestData(requestContext, authentication);

            throw new AccessDeniedException("Access denied, illegal JwtAuthenticationToken: " + authentication.getClass().getName());
        }

        String userName = getUserNameFromToken(jwtToken);
        boolean authenticated = authentication.isAuthenticated();
        log.info("User {} got authentication result {}", userName, authenticated);

        if (!authenticated) {
            log.info("User not authenticated, access denied");
            throw new AccessDeniedException("User not authenticated, access is denied");
        }

        if (!isLocalhost()) {
            if (hasAdminRole(jwtToken) && hasCorrectOrgId(jwtToken)) {
                log.info("User has admin role, access granted");
                return new AuthorizationDecision(true);
            }

            if (!hasRoleAndAuthority(jwtToken)) {
                log.warn("Access denied, not correct role or org");
                throw new AccessDeniedException("Access is denied. Not correct org or role");
            }
        }

        boolean authorized = authorizationClient.isAuthorized(userName, getRequestMethod(requestContext), authenticationUtil.getUrl());

        if (!authorized) {
            log.info("User not authorized, access denied");
            throw new AccessDeniedException("User not authorized, access is denied");
        }

        return new AuthorizationDecision(true);
    }

    private void logInvalidTokenRequestData(RequestAuthorizationContext requestContext, Authentication authentication) {
        Enumeration<String> headerNames = requestContext.getRequest().getHeaderNames();
        Map<String, String> collect = Collections.emptyMap();

        if (headerNames != null) {
            collect = Collections.list(headerNames)
                    .stream()
                    .collect(Collectors.toMap(
                            name -> name,
                            name -> requestContext.getRequest().getHeader(name)
                    ));
        }
        log.warn("Illegal jwt token: {}. Request URI: {}. Request servlet path: {}. Headers: {}",
                 authentication.getClass().getName(),
                 requestContext.getRequest().getRequestURI(),
                 requestContext.getRequest().getServletPath(),
                 collect
        );
    }

    private boolean isLocalhost() {
        log.info("Environment is: {}", baseUrl);

        if (baseUrl.equals("localhost")) {
            log.info("Auth: Is localhost");
            return true;
        }

        return false;
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
        boolean hasAuthority = hasCorrectOrgId(jwtToken);

        return hasRole && hasAuthority;
    }

    private boolean hasCorrectOrgId(JwtAuthenticationToken jwtToken) {
        return jwtToken.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ORGID_" + authorizedOrgId));
    }

    boolean hasAdminRole(JwtAuthenticationToken jwtToken) {
        log.info("Auth: Listing all roles found on jwt token");
        jwtToken.getAuthorities().forEach(a -> log.info("Authorities in jwt: {}", a.getAuthority()));

        List<String> roles = (List<String>) jwtToken.getTokenAttributes().get("roles");
        if (roles != null) {
            log.info("Auth: Listing all roles found on token attributes");
            roles.forEach(r -> log.info("Roles in token attributes: {}", r));
        }

        boolean hasAdmin = jwtToken.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + adminRole));

        log.info("Auth: Has admin role: {}", hasAdmin);

        return hasAdmin;
    }

    protected void setAdminRole(String adminRole) {
        this.adminRole = adminRole;
    }

    protected void setAuthorizedRole(String authorizedRole) {
        this.authorizedRole = authorizedRole;
    }

    protected void setAuthorizedOrgId(String authorizedOrgId) {
        this.authorizedOrgId = authorizedOrgId;
    }

    protected void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }
}
