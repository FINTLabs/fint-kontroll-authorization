package no.fintlabs.opa;

public class AuthorizationClientTest {

    /*private OpaApiClient opaApiClient;
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
        when(opaApiClient.hasUserAuthorization("ragnild.hansen@viken.no", "GET")).thenReturn(Mono.just(true));

        Mono<Boolean> authorized = authorizationClient.isAuthorized("ragnild.hansen@viken.no", "GET");

        StepVerifier.create(authorized)
                .expectNext(true)
                .verifyComplete();

        verify(opaApiClient, times(1)).hasUserAuthorization(any(), any());
    }

    @Test
    public void unknownUserShouldNotBeAuthorized() {
        when(opaApiClient.hasUserAuthorization("ragnild.hansen@viken.no", "GET")).thenReturn(Mono.just(false));

        Mono<Boolean> authorized = authorizationClient.isAuthorized("ragnild.hansen@viken.no", "GET");

        StepVerifier.create(authorized)
                .expectNext(false)
                .verifyComplete();

        verify(opaApiClient, times(1)).hasUserAuthorization(any(), any());
    }

    @Test
    public void shouldGetUserScopes() {
        String userName = "ragnild.hansen@viken.no";

        when(authenticationUtil.isAuthenticated()).thenReturn(Mono.just(true));
        when(authenticationUtil.getUserName()).thenReturn(Mono.just(userName));

        LinkedHashMap<String, Object> map = new LinkedHashMap<>();
        map.put("result", "true");

        when(opaApiClient.getScopesForUser(userName)).thenReturn(Mono.just(map));

        Mono<LinkedHashMap> scopes = authorizationClient.getUserScopes();

        StepVerifier.create(scopes)
                .expectNext(map)
                .verifyComplete();

        verify(opaApiClient, times(1)).getScopesForUser(any());
        verify(authenticationUtil, times(1)).getUserName();
        verify(authenticationUtil, times(1)).isAuthenticated();
    }

    @Test
    public void shouldNotGetUserScopesIfNotAuthenticated() {
        when(authenticationUtil.isAuthenticated()).thenReturn(Mono.just(false));

        Mono<LinkedHashMap> scopes = authorizationClient.getUserScopes();

        StepVerifier.create(scopes)
                .verifyComplete();

        verify(opaApiClient, times(0)).getScopesForUser(any());
    }*/
}
