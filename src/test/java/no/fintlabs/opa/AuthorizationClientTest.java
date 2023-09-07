package no.fintlabs.opa;

import no.fintlabs.opa.model.Scope;
import no.fintlabs.util.AuthenticationUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

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
        when(opaApiClient.hasUserAuthorization("ragnild.hansen@viken.no", "GET")).thenReturn(true);

        Boolean authorized = authorizationClient.isAuthorized("ragnild.hansen@viken.no", "GET");

        assertTrue(authorized);
    }

    @Test
    public void unknownUserShouldNotBeAuthorized() {
        when(opaApiClient.hasUserAuthorization("unknown@viken.no", "GET")).thenReturn(false);

        Boolean authorized = authorizationClient.isAuthorized("unknown@viken.no", "GET");

        assertFalse(authorized);

        verify(opaApiClient, times(1)).hasUserAuthorization("unknown@viken.no", "GET");
    }

    @Test
    public void shouldGetUserScopes() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAuthenticated()).thenReturn(true);
        when(authenticationUtil.getUserName()).thenReturn(userName);

        Scope scope1 = Scope.builder()
                .id("1")
                .objectType("user")
                .orgUnits(List.of("198", "2", "3"))
                .build();

        Scope scope2 = Scope.builder()
                .id("2")
                .objectType("role")
                .orgUnits(List.of("198", "2", "3"))
                .build();

        List<Scope> scopes = List.of(scope1, scope2);

        when(opaApiClient.getScopesForUser(userName)).thenReturn(scopes);

        List<Scope> foundScopes = authorizationClient.getUserScopes();

        assertEquals(2, foundScopes.size());
        assertEquals("1", foundScopes.get(0).getId());
        assertEquals("user", foundScopes.get(0).getObjectType());
        assertEquals(3, foundScopes.get(0).getOrgUnits().size());
        assertEquals("198", foundScopes.get(0).getOrgUnits().get(0));
        assertEquals("2", foundScopes.get(0).getOrgUnits().get(1));
        assertEquals("3", foundScopes.get(0).getOrgUnits().get(2));

        verify(opaApiClient, times(1)).getScopesForUser(userName);
        verify(authenticationUtil, times(1)).getUserName();
        verify(authenticationUtil, times(1)).isAuthenticated();
    }

    @Test
    public void shouldNotGetUserScopesIfNotAuthenticated() {
        when(authenticationUtil.isAuthenticated()).thenReturn(false);

        List<Scope> scopes = authorizationClient.getUserScopes();

        assertEquals(0, scopes.size());

        verify(opaApiClient, times(0)).getScopesForUser(any());
    }
}
