package no.fintlabs.util;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import no.vigoiks.resourceserver.security.FintJwtEndUserPrincipal;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@Slf4j
@Component
public class AuthenticationUtil {
    @Value("${fint.kontroll.authorization.authorized-admin-role:admin}")
    private String adminRole;

    public String getUserName() {
        log.debug("Getting user name");

        SecurityContext securityContext = getSecurityContext();

        Authentication authentication = securityContext.getAuthentication();
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        Jwt principal = (Jwt) jwtToken.getPrincipal();
        FintJwtEndUserPrincipal fintJwtEndUserPrincipal = FintJwtEndUserPrincipal.from(principal);
        return fintJwtEndUserPrincipal.getMail() != null ? fintJwtEndUserPrincipal.getMail() : "";
    }

    public Boolean isAuthenticated() {
        log.debug("Checking if user is authenticated");

        SecurityContext securityContext = getSecurityContext();
        Authentication authentication = securityContext.getAuthentication();
        return authentication.isAuthenticated();
    }

    private SecurityContext getSecurityContext() {
        return SecurityContextHolder.getContext();
    }

    public String getUrl() {
        log.debug("Getting requested url");

        SecurityContext securityContext = getSecurityContext();
        Authentication authentication = securityContext.getAuthentication();
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        Jwt principal = (Jwt) jwtToken.getPrincipal();
        FintJwtEndUserPrincipal fintJwtEndUserPrincipal = FintJwtEndUserPrincipal.from(principal);
        String orgId = fintJwtEndUserPrincipal.getOrgId() != null ? fintJwtEndUserPrincipal.getOrgId() : "";

        log.debug("Found orgId: {}", orgId);
        if (RequestContextHolder.getRequestAttributes() == null) {
            return "";
        }

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        String requestURI = request.getRequestURI();

        log.debug("Request URI: {}", requestURI);
        orgId = orgId.replace(".", "-");

        requestURI = requestURI.replace("/" + orgId, "");
        requestURI = requestURI.replace("/beta/fintlabs-no", "");
        requestURI = requestURI.replace("/fintlabs-no", "");

        log.debug("Stripped request URI: {}", requestURI);
        return requestURI;
    }

    public boolean isAdmin() {
        log.debug("Checking if user is admin");

        SecurityContext securityContext = getSecurityContext();
        Authentication authentication = securityContext.getAuthentication();
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        return hasAdminRole(jwtToken);
    }

    boolean hasAdminRole(JwtAuthenticationToken jwtToken) {
        boolean hasAdmin = jwtToken.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + adminRole));

        log.debug("AuthUtil: Has admin role: {}", hasAdmin);

        return hasAdmin;
    }
}
