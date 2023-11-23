package no.fintlabs.opa;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.Set;
import java.util.function.Supplier;

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
    private Supplier<JwtAuthenticationToken> jwtAuthenticationToken;

    @Mock
    private Jwt principal;

    @Mock
    private RequestAuthorizationContext requestAuthorizationContext;

    private Supplier<Authentication> auth;

    @Mock
    private HttpServletRequest httpServletRequest;

    @BeforeEach
    public void setUp() {
        httpServletRequest = mock(HttpServletRequest.class);
        when(requestAuthorizationContext.getRequest()).thenReturn(httpServletRequest);
        kontrollAuthorizationManager.setBaseUrl("api");
    }

    private void setupAuth() {
        JwtAuthenticationToken jwtAuthenticationTokenMock = mock(JwtAuthenticationToken.class);
        when(jwtAuthenticationToken.get()).thenReturn(jwtAuthenticationTokenMock);
        auth = () -> jwtAuthenticationToken.get();
    }
    @Test
    public void testDecide_Authorized() {
        setupAuth();
        setupAuthorizedUser();

        when(httpServletRequest.getRequestURI()).thenReturn("/api/orgunits");
        when(auth.get().isAuthenticated()).thenReturn(true);

        assertDoesNotThrow(() -> {
            kontrollAuthorizationManager.check(auth, requestAuthorizationContext);
        });
    }

    @Test
    public void testDecide_Authorized_adminRole() {
        setupAuth();
        setupAuthorizedAdmin();

        when(httpServletRequest.getRequestURI()).thenReturn("/api/orgunits");
        when(auth.get().isAuthenticated()).thenReturn(true);

        assertDoesNotThrow(() -> {
            kontrollAuthorizationManager.check(auth, requestAuthorizationContext);
        });
    }

    @Test
    public void testDecide_Authorized_accessmanagement_adminRole() {
        setupAuth();
        setupAuthorizedAdmin();

        when(httpServletRequest.getRequestURI()).thenReturn("/api/accessmanagement");
        when(auth.get().isAuthenticated()).thenReturn(true);

        assertDoesNotThrow(() -> {
            kontrollAuthorizationManager.check(auth, requestAuthorizationContext);
        });
    }

    @Test
    public void testDecide_UnAuthorized_accessmanagement_not_admin() {
        setupAuth();
        when(jwtAuthenticationToken.get().getPrincipal()).thenReturn(principal);

        when(httpServletRequest.getRequestURI()).thenReturn("/api/accessmanagement");
        when(auth.get().isAuthenticated()).thenReturn(true);

        assertThrows(AccessDeniedException.class, () -> kontrollAuthorizationManager.check(auth, requestAuthorizationContext));
    }

    @Test
    public void testDecide_Unauthorized() {
        setupAuth();
        setupUnAuthorizedUser();

        when(auth.get().isAuthenticated()).thenReturn(true);

        when(httpServletRequest.getRequestURI()).thenReturn("/testunauthorized");

        assertThrows(AccessDeniedException.class, () -> kontrollAuthorizationManager.check(auth, requestAuthorizationContext));
    }

    @Test
    public void testDecide_NotJwtAuthentication() {
        Supplier<Authentication> notJwtAuth = () -> new TestingAuthenticationToken(null, null);

        when(httpServletRequest.getRequestURI()).thenReturn("/api/orgunits");

        assertThrows(AccessDeniedException.class, () -> kontrollAuthorizationManager.check(notJwtAuth, requestAuthorizationContext));
    }

    @Test
    public void testDecide_Swagger() {
        Supplier<Authentication> notJwtAuth = () -> new TestingAuthenticationToken(null, null);

        when(httpServletRequest.getRequestURI()).thenReturn("/swagger-ui");

        assertDoesNotThrow(() -> kontrollAuthorizationManager.check(notJwtAuth, requestAuthorizationContext));
    }

    private void setupUnAuthorizedUser() {
        expectRoleAndOrg();

        when(httpServletRequest.getMethod()).thenReturn("GET");
        when(jwtAuthenticationToken.get().getPrincipal()).thenReturn(principal);
        when(authorizationClient.isAuthorized(anyString(), anyString())).thenReturn(false);
    }

    private void expectAdminRoleAndOrg() {
        GrantedAuthority grantedAuthorityRole = new SimpleGrantedAuthority("ROLE_admin");
        GrantedAuthority grantedAuthorityOrg = new SimpleGrantedAuthority("ORGID_vigo.no");

        kontrollAuthorizationManager.setAdminRole("admin");
        kontrollAuthorizationManager.setAuthorizedOrgId("vigo.no");

        when(jwtAuthenticationToken.get().getAuthorities()).thenReturn(Set.of(grantedAuthorityRole, grantedAuthorityOrg));
    }

    private void expectRoleAndOrg() {
        GrantedAuthority grantedAuthorityRole = new SimpleGrantedAuthority("ROLE_rolle");
        GrantedAuthority grantedAuthorityOrg = new SimpleGrantedAuthority("ORGID_vigo.no");

        kontrollAuthorizationManager.setAuthorizedRole("rolle");
        kontrollAuthorizationManager.setAuthorizedOrgId("vigo.no");

        when(jwtAuthenticationToken.get().getAuthorities()).thenReturn(Set.of(grantedAuthorityRole, grantedAuthorityOrg));
    }

    private void setupAuthorized() {
        when(httpServletRequest.getMethod()).thenReturn("GET");
        when(jwtAuthenticationToken.get().getPrincipal()).thenReturn(principal);
        when(authorizationClient.isAuthorized(anyString(), anyString())).thenReturn(true);
    }

    private void setupAuthorizedAdmin() {
        expectAdminRoleAndOrg();
        when(jwtAuthenticationToken.get().getPrincipal()).thenReturn(principal);
    }

    private void setupAuthorizedUser() {
        expectRoleAndOrg();
        setupAuthorized();
    }

}
