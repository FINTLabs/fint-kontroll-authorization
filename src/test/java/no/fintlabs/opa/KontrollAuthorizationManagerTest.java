package no.fintlabs.opa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class KontrollAuthorizationManagerTest {

    @InjectMocks
    private KontrollAuthorizationManager kontrollAuthorizationManager;

    @Mock
    private AuthorizationClient authorizationClient;

    @Mock
    private JwtAuthenticationToken jwtAuthenticationToken;

    @Mock
    private Jwt principal;

    private HttpServletRequest httpServletRequest;

    @BeforeEach
    public void setUp() {
        httpServletRequest = mock(HttpServletRequest.class);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(httpServletRequest));
    }

    @Test
    public void testDecide_Authorized() {
        setupAuthorizedUser();

        when(httpServletRequest.getRequestURI()).thenReturn("/api/orgunits");

        assertDoesNotThrow(() -> {
            kontrollAuthorizationManager.decide(jwtAuthenticationToken, new Object(), mock(Collection.class));
        });
    }

    @Test
    public void testDecide_Unauthorized() {
        setupUnAuthorizedUser();

        when(httpServletRequest.getRequestURI()).thenReturn("/testunauthorized");

        assertThrows(AccessDeniedException.class, () -> {
            kontrollAuthorizationManager.decide(jwtAuthenticationToken, new Object(), mock(Collection.class));
        });
    }

    @Test
    public void testDecide_NotJwtAuthentication() {
        Authentication notJwtAuth = mock(Authentication.class);

        when(httpServletRequest.getRequestURI()).thenReturn("/api/orgunits");

        assertThrows(AccessDeniedException.class, () -> kontrollAuthorizationManager.decide(notJwtAuth, new Object(), mock(Collection.class)));
    }

    @Test
    public void testDecide_Swagger() {
        Authentication notJwtAuth = mock(Authentication.class);

        when(httpServletRequest.getRequestURI()).thenReturn("/swagger-ui");

        assertDoesNotThrow(() -> kontrollAuthorizationManager.decide(notJwtAuth, new Object(), mock(Collection.class)));
    }

    private void setupUnAuthorizedUser() {
        expectRoleAndOrg();

        when(httpServletRequest.getMethod()).thenReturn("GET");
        when(jwtAuthenticationToken.getPrincipal()).thenReturn(principal);
        when(authorizationClient.isAuthorized(anyString(), anyString())).thenReturn(false);
    }

    private void expectRoleAndOrg() {
        GrantedAuthority grantedAuthorityRole = new SimpleGrantedAuthority("ROLE_rolle");
        GrantedAuthority grantedAuthorityOrg = new SimpleGrantedAuthority("ORGID_vigo.no");

        kontrollAuthorizationManager.setAuthorizedRole("rolle");
        kontrollAuthorizationManager.setAuthorizedOrgId("vigo.no");

        when(jwtAuthenticationToken.getAuthorities()).thenReturn(Set.of(grantedAuthorityRole, grantedAuthorityOrg));
    }

    private void setupAuthorizedUser() {
        expectRoleAndOrg();

        when(httpServletRequest.getMethod()).thenReturn("GET");
        when(jwtAuthenticationToken.getPrincipal()).thenReturn(principal);
        when(authorizationClient.isAuthorized(anyString(), anyString())).thenReturn(true);
    }

}
