package no.fintlabs.opa;

import no.vigoiks.resourceserver.security.FintJwtEndUserPrincipal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class OpaAuthorizationManagerTest {
    @Mock
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


    }

}
