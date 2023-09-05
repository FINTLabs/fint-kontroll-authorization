package no.fintlabs.opa;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import no.vigoiks.resourceserver.security.FintJwtEndUserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
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
public class OpaAuthorizationManagerSync implements AccessDecisionManager {

    @Autowired
    private AuthorizationClientSync authorizationClient;

    @Override
    public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException, InsufficientAuthenticationException {
        if (!(authentication instanceof JwtAuthenticationToken)) {
            throw new AccessDeniedException("Not a JwtAuthenticationToken");
        }

        JwtAuthenticationToken jwtToken = (JwtAuthenticationToken) authentication;
        Jwt principal = (Jwt) jwtToken.getPrincipal();
        FintJwtEndUserPrincipal fintJwtEndUserPrincipal = FintJwtEndUserPrincipal.from(principal);
        String userName = fintJwtEndUserPrincipal.getMail() != null ? fintJwtEndUserPrincipal.getMail() : "";

        String principalName = (String) principal.getClaims().get("principalName");
        log.info("Fant principalName {}", principalName);

        ServletRequestAttributes sra = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();

        log.info("Request method {}", sra.getRequest().getMethod());
        log.info("Request path {}", sra.getRequest().getRequestURI());

        boolean authenticated = authentication.isAuthenticated();
        log.info("Authenticated {}", authenticated);

        log.info("Checking if user is authorized in opa with username {}", userName);

        boolean authorized = authorizationClient.isAuthorized(userName, sra.getRequest().getMethod());

        if (!authorized) {
            throw new AccessDeniedException("Access is denied");
        }
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }
}
