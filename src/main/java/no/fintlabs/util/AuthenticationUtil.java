package no.fintlabs.util;

import lombok.extern.slf4j.Slf4j;
import no.vigoiks.resourceserver.security.FintJwtEndUserPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationUtil {
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
}
