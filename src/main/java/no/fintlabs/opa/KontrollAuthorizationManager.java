package no.fintlabs.opa;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.vigoiks.resourceserver.security.FintJwtEndUserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Collection;

@Slf4j
@RequiredArgsConstructor
@Component
public class KontrollAuthorizationManager implements AccessDecisionManager {

    @Autowired
    private AuthorizationClient authorizationClient;

    @Value("${fint.kontroll.authorization.authorized-role:rolle}")
    private String authorizedRole;

    @Value("${fint.kontroll.authorization.authorized-org-id:vigo.no}")
    private String authorizedOrgId;


    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException, InsufficientAuthenticationException {

        if (!(authentication instanceof JwtAuthenticationToken)) {
            throw new AccessDeniedException("Not a JwtAuthenticationToken");
        }

        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;

        if (!hasRoleAndAuthority(jwtToken)) {
            throw new AccessDeniedException("Access is denied. Not correct org or role");
        }

        String userName = getUserNameFromToken(jwtToken);

        boolean authenticated = authentication.isAuthenticated();
        log.info("User {} got authentication result {}", userName, authenticated);

        boolean authorized = authorizationClient.isAuthorized(userName, getRequestMethod());

        if (!authorized) {
            throw new AccessDeniedException("User not authorized, access is denied");
        }
    }

    private static String getRequestMethod() {
        ServletRequestAttributes sra = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        log.info("Request method {}", sra.getRequest().getMethod());
        log.info("Request path {}", sra.getRequest().getRequestURI());
        return sra.getRequest().getMethod();
    }

    private String getUserNameFromToken(JwtAuthenticationToken jwtToken) {
        Jwt principal = (Jwt) jwtToken.getPrincipal();
        FintJwtEndUserPrincipal fintJwtEndUserPrincipal = FintJwtEndUserPrincipal.from(principal);
        return fintJwtEndUserPrincipal.getMail() != null ? fintJwtEndUserPrincipal.getMail() : "";
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    private boolean hasRoleAndAuthority(JwtAuthenticationToken jwtToken) {
        boolean hasRole = jwtToken.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + authorizedRole));
        boolean hasAuthority = jwtToken.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ORGID_" + authorizedOrgId));

        return hasRole && hasAuthority;
    }

    protected void setAuthorizedRole(String authorizedRole) {
        this.authorizedRole = authorizedRole;
    }

    protected void setAuthorizedOrgId(String authorizedOrgId) {
        this.authorizedOrgId = authorizedOrgId;
    }
}
