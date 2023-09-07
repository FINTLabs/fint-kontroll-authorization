package no.fintlabs.opa;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class OpaAuthorizationManagerTest {

    @InjectMocks
    private OpaAuthorizationManager opaAuthorizationManager;

    @Mock
    private AuthorizationClient authorizationClient;

    @Mock
    private JwtAuthenticationToken jwtAuthenticationToken;

    @Mock
    private Jwt principal;

    @Test
    public void testDecide_Authorized() {
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(httpServletRequest));

        when(httpServletRequest.getMethod()).thenReturn("GET");

        when(jwtAuthenticationToken.getPrincipal()).thenReturn(principal);
        when(principal.getClaims()).thenReturn(Map.of("principalName", "john.doe"));
        when(authorizationClient.isAuthorized(anyString(), anyString())).thenReturn(true);

        assertDoesNotThrow(() -> {
            opaAuthorizationManager.decide(jwtAuthenticationToken, new Object(), mock(Collection.class));
        });
    }

    @Test
    public void testDecide_Unauthorized() {
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(httpServletRequest));

        when(httpServletRequest.getMethod()).thenReturn("GET");

        when(jwtAuthenticationToken.getPrincipal()).thenReturn(principal);
        when(principal.getClaims()).thenReturn(Map.of("principalName", "john.doe"));
        when(authorizationClient.isAuthorized(anyString(), anyString())).thenReturn(false);

        assertThrows(AccessDeniedException.class, () -> {
            opaAuthorizationManager.decide(jwtAuthenticationToken, new Object(), mock(Collection.class));
        });
    }

    @Test
    public void testDecide_NotJwtAuthentication() {
        Authentication notJwtAuth = mock(Authentication.class);

        assertThrows(AccessDeniedException.class, () -> {
            opaAuthorizationManager.decide(notJwtAuth, new Object(), mock(Collection.class));
        });
    }

}
