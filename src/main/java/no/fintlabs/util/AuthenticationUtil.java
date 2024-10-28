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

import java.util.List;

@Slf4j
@Component
public class AuthenticationUtil {
    @Value("${fint.kontroll.authorization.authorized-admin-role:admin}")
    private String adminRole;

    public String getUserName() {
        log.info("Getting user name");

        SecurityContext securityContext = getSecurityContext();
        log.info("Got security context {}", securityContext);

        Authentication authentication = securityContext.getAuthentication();
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        Jwt principal = (Jwt) jwtToken.getPrincipal();
        FintJwtEndUserPrincipal fintJwtEndUserPrincipal = FintJwtEndUserPrincipal.from(principal);
        return fintJwtEndUserPrincipal.getMail() != null ? fintJwtEndUserPrincipal.getMail() : "";
    }

    public Boolean isAuthenticated() {
        log.info("Checking if user is authenticated");

        SecurityContext securityContext = getSecurityContext();
        log.info("Got security context {}", securityContext);
        Authentication authentication = securityContext.getAuthentication();
        return authentication.isAuthenticated();
    }

    private SecurityContext getSecurityContext() {
        return SecurityContextHolder.getContext();
    }

    public String getUrl() {
        log.info("Getting requested url");

        SecurityContext securityContext = getSecurityContext();
        Authentication authentication = securityContext.getAuthentication();
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        Jwt principal = (Jwt) jwtToken.getPrincipal();
        FintJwtEndUserPrincipal fintJwtEndUserPrincipal = FintJwtEndUserPrincipal.from(principal);
        String orgId = fintJwtEndUserPrincipal.getOrgId() != null ? fintJwtEndUserPrincipal.getOrgId() : "";

        log.info("Found orgId: {}", orgId);
        if (RequestContextHolder.getRequestAttributes() == null) {
            return "";
        }

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        String requestURI = request.getRequestURI();

        log.info("Request URI: {}", requestURI);
        orgId = orgId.replace(".", "-");

        requestURI = requestURI.replace("/" + orgId, "");
        requestURI = requestURI.replace("/beta/fintlabs-no", "");

        log.info("Stripped request URI: {}", requestURI);
        return requestURI;
    }

    public boolean isAdmin() {
        log.info("Checking if user is admin");

        SecurityContext securityContext = getSecurityContext();
        Authentication authentication = securityContext.getAuthentication();
        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        return hasAdminRole(jwtToken);
    }

    boolean hasAdminRole(JwtAuthenticationToken jwtToken) {
        log.info("AuthUtil: Listing all roles found on jwt token");
        jwtToken.getAuthorities().forEach(a -> log.info("Authorities in jwt: {}", a.getAuthority()));

        List<String> roles = (List<String>) jwtToken.getTokenAttributes().get("roles");
        if (roles != null) {
            log.info("Auth: Listing all roles found on token attributes");
            roles.forEach(r -> log.info("Roles in token attributes: {}", r));
        }

        boolean hasAdmin = jwtToken.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + adminRole));

        log.info("AuthUtil: Has admin role: {}", hasAdmin);

        return hasAdmin;
    }
}
