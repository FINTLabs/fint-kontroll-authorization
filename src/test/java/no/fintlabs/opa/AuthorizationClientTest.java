package no.fintlabs.opa;

import no.fintlabs.opa.model.AuthRole;
import no.fintlabs.opa.model.AuthorizedRole;
import no.fintlabs.opa.model.MenuItem;
import no.fintlabs.opa.model.Scope;
import no.fintlabs.util.AuthenticationUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class AuthorizationClientTest {

    private OpaApiClient opaApiClient;
    private AuthenticationUtil authenticationUtil;
    private AuthorizationClient authorizationClient;

    @BeforeEach
    public void setUp() {
        opaApiClient = mock(OpaApiClient.class);
        authenticationUtil = mock(AuthenticationUtil.class);
        authorizationClient = new AuthorizationClient(opaApiClient, authenticationUtil);
    }

    @Test
    public void shouldBeAuthorized() {
        String url = "http://localhost:8080/api/orgunits";

        when(opaApiClient.hasUserAuthorization("ragnild.hansen@viken.no", "GET", url)).thenReturn(true);

        Boolean authorized = authorizationClient.isAuthorized("ragnild.hansen@viken.no", "GET", url);

        assertTrue(authorized);
    }

    @Test
    public void unknownUserShouldNotBeAuthorized() {
        String url = "http://localhost:8080/api/orgunits";

        when(opaApiClient.hasUserAuthorization("unknown@viken.no", "GET", url)).thenReturn(false);

        Boolean authorized = authorizationClient.isAuthorized("unknown@viken.no", "GET", url);

        assertFalse(authorized);

        verify(opaApiClient, times(1)).hasUserAuthorization("unknown@viken.no", "GET", url);
    }

    @Test
    public void shouldGetUserScopesFromList() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);
        when(authenticationUtil.getUrl()).thenReturn("/api/test");

        Scope scope1 = Scope.builder()
                .objectType("user")
                .orgUnits(List.of("198", "2", "3"))
                .build();

        Scope scope2 = Scope.builder()
                .objectType("role")
                .orgUnits(List.of("198", "2", "3"))
                .build();

        List<Scope> scopes = List.of(scope1, scope2);

        when(opaApiClient.getScopesListForUser(userName, "/api/test")).thenReturn(scopes);

        List<Scope> foundScopes = authorizationClient.getUserScopesList();

        assertEquals(2, foundScopes.size());
        assertEquals("user", foundScopes.get(0).getObjectType());
        assertEquals(3, foundScopes.get(0).getOrgUnits().size());
        assertEquals("198", foundScopes.get(0).getOrgUnits().get(0));
        assertEquals("2", foundScopes.get(0).getOrgUnits().get(1));
        assertEquals("3", foundScopes.get(0).getOrgUnits().get(2));

        verify(opaApiClient, times(1)).getScopesListForUser(userName, "/api/test");
        verify(authenticationUtil, times(1)).getUserName();
        verify(authenticationUtil, times(1)).isAuthenticated();
    }

    @Test
    public void shouldGetRoles() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);
        when(authenticationUtil.getUrl()).thenReturn("/api/test");

        when(opaApiClient.getRolesForUser(userName, "/api/test")).thenReturn(List.of("sa", "ra"));

        List<String> roles = authorizationClient.getRoles();

        assertEquals(2, roles.size());
        assertEquals("sa", roles.get(0));
        assertEquals("ra", roles.get(1));

        verify(opaApiClient, times(1)).getRolesForUser(userName, "/api/test");
        verify(authenticationUtil, times(1)).getUserName();
        verify(authenticationUtil, times(1)).isAuthenticated();
    }


    @Test
    public void shouldNotGetUserScopesIfNotAuthenticated() {
        when(authenticationUtil.isAuthenticated()).thenReturn(false);

        List<Scope> scopes = authorizationClient.getUserScopesList();

        assertEquals(0, scopes.size());

        verify(opaApiClient, times(0)).getScopesListForUser(any(), any());
    }

    @Test
    public void shouldGetUserRoles() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAdmin()).thenReturn(false);
        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);
        when(authenticationUtil.getUrl()).thenReturn("/api/test");
        when(opaApiClient.getRolesForUser(userName, "/api/test")).thenReturn(List.of("td"));

        List<AuthRole> userRoles = authorizationClient.getUserRoles();

        assertThat(userRoles).isNotEmpty();
        assertThat(userRoles).hasSize(1);
        assertThat(userRoles.getFirst().getName()).isEqualTo(AuthorizedRole.TILDELER.getName());
        assertThat(userRoles.getFirst().getId()).isEqualTo(AuthorizedRole.TILDELER.getShortName());
    }

    @Test
    public void shouldGetMenuItemsForUser() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAdmin()).thenReturn(false);
        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);
        when(authenticationUtil.getUrl()).thenReturn("/api/test");
        when(opaApiClient.getMenuItemsForUser(userName, "/api/test")).thenReturn(List.of(new MenuItem( "/beta/test/url", "Test url beta")));

        List<MenuItem> menuItems = authorizationClient.getMenuItems();

        assertThat(menuItems).isNotEmpty();
        assertThat(menuItems).hasSize(1);
        assertThat(menuItems.getFirst().text()).isEqualTo("Test url beta");
        assertThat(menuItems.getFirst().url()).isEqualTo("/beta/test/url");
    }

    @Test
    public void shouldGetUserRolesAsAdmin() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAdmin()).thenReturn(true);
        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);
        when(authenticationUtil.getUrl()).thenReturn("/api/test");
        when(opaApiClient.getRolesForUser(userName, "/api/test")).thenReturn(List.of("td"));

        List<AuthRole> userRoles = authorizationClient.getUserRoles();

        assertThat(userRoles).isNotEmpty();
        assertThat(userRoles).hasSize(2);
        assertThat(userRoles.getFirst().getName()).isEqualTo(AuthorizedRole.PORTAL_ADMIN.getName());
        assertThat(userRoles.getFirst().getId()).isEqualTo(AuthorizedRole.PORTAL_ADMIN.getShortName());
        assertThat(userRoles.get(1).getName()).isEqualTo(AuthorizedRole.TILDELER.getName());
        assertThat(userRoles.get(1).getId()).isEqualTo(AuthorizedRole.TILDELER.getShortName());
    }

    @Test
    public void shouldBeAllowedToCreateAccessAssignment() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);
        when(authenticationUtil.getUrl()).thenReturn("/api/test");
        when(opaApiClient.getRolesForUser(userName, "/api/test")).thenReturn(List.of("td"));

        when(authenticationUtil.isAdmin()).thenReturn(true);

        assertTrue(authorizationClient.canManageAccessAssignment(AuthorizedRole.SYSTEM_ADMIN.getShortName()));

        when(opaApiClient.getRolesForUser(userName, "/api/test")).thenReturn(List.of("sa"));
        when(authenticationUtil.isAdmin()).thenReturn(false);

        assertTrue(authorizationClient.canManageAccessAssignment(AuthorizedRole.SYSTEM_ADMIN.getShortName()));

        when(opaApiClient.getRolesForUser(userName, "/api/test")).thenReturn(List.of("ra"));

        assertTrue(authorizationClient.canManageAccessAssignment(AuthorizedRole.TJENESTE_ADMIN.getShortName()));
        assertTrue(authorizationClient.canManageAccessAssignment(AuthorizedRole.TILDELER.getShortName()));
    }

    @Test
    public void shouldNotBeAllowedToCreateSysadminRessursAdminAsRessursadmin() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);
        when(authenticationUtil.getUrl()).thenReturn("/api/test");
        when(authenticationUtil.isAdmin()).thenReturn(false);

        when(opaApiClient.getRolesForUser(userName, "/api/test")).thenReturn(List.of("ra"));

        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.SYSTEM_ADMIN.getShortName()));
        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.RESSURS_ADMIN.getShortName()));
        assertTrue(authorizationClient.canManageAccessAssignment(AuthorizedRole.TJENESTE_ADMIN.getShortName()));
    }

    @Test
    public void shouldNotBeAllowedToCreateSysadminRessursTjenesteAdminAsTjenesteadmin() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);
        when(authenticationUtil.getUrl()).thenReturn("/api/test");
        when(authenticationUtil.isAdmin()).thenReturn(false);

        when(opaApiClient.getRolesForUser(userName, "/api/test")).thenReturn(List.of("ta"));

        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.SYSTEM_ADMIN.getShortName()));
        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.RESSURS_ADMIN.getShortName()));
        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.TJENESTE_ADMIN.getShortName()));
        assertTrue(authorizationClient.canManageAccessAssignment(AuthorizedRole.TILDELER.getShortName()));
    }

    @Test
    public void shouldNotBeAllowedToCreateAnyAsTildeler() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);
        when(authenticationUtil.getUrl()).thenReturn("/api/test");
        when(authenticationUtil.isAdmin()).thenReturn(false);

        when(opaApiClient.getRolesForUser(userName, "/api/test")).thenReturn(List.of("td"));

        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.SYSTEM_ADMIN.getShortName()));
        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.RESSURS_ADMIN.getShortName()));
        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.TJENESTE_ADMIN.getShortName()));
        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.TILDELER.getShortName()));
        assertFalse(authorizationClient.canManageAccessAssignment(AuthorizedRole.LEDER.getShortName()));
    }
}
