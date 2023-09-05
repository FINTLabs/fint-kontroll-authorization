package no.fintlabs.opa;

import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class OpaAuthorizationManagerTest {
    /*@Mock
    private AuthorizationClient authorizationClient;

    @InjectMocks
    private OpaAuthorizationManager opaAuthorizationManager;

    @Test
    public void testCheckUserAuthorized() {
        String userName = "ragnhild.hansen@viken.no";
        String principalName = "testPrincipalName";
        HttpMethod requestMethod = HttpMethod.GET;

        Jwt jwt = new Jwt("tokenValue", Instant.now(), Instant.now().plusSeconds(3600),
                          Collections.singletonMap("principalName", principalName), Map.of("email", "ragnhild.hansen@viken.no"));

        JwtAuthenticationToken jwtToken = new JwtAuthenticationToken(jwt);

        ServerHttpRequest serverHttpRequest = mock(ServerHttpRequest.class);
        when(serverHttpRequest.getMethod()).thenReturn(requestMethod);

        ServerWebExchange serverWebExchange = mock(ServerWebExchange.class);
        when(serverWebExchange.getRequest()).thenReturn(serverHttpRequest);

        AuthorizationContext context = new AuthorizationContext(serverWebExchange);

        when(authorizationClient.isAuthorized(userName, requestMethod.name())).thenReturn(Mono.just(true));

        StepVerifier.create(opaAuthorizationManager.check(Mono.just(jwtToken), context))
                .assertNext(decision -> assertEquals(true, decision.isGranted()))
                .verifyComplete();


    }*/

}
