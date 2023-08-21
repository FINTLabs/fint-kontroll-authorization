package no.fintlabs.opa;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OpaClientTest {

    /*@Test
    public void shouldBeAuthorized() {
        WebClient restTemplate = mock(WebClient.class);

        when(restTemplate.post( isA(String.class), isA(Map.class), any())).thenReturn(new OpaClient.OpaResponse("true"));

        OpaClient opaClient = new OpaClient().setWebClient(restTemplate);
        opaClient = opaClient.setOpaUrl("http://dummy.url/");
        boolean isAuthorized = opaClient.isAuthorized("ragnild.hansen@viken.no", "GET");

        assertThat(isAuthorized).isTrue();

        verify(restTemplate).postForObject(isA(String.class), isA(Map.class), any());
    }

    @Test
    public void unknownUserShouldNotBeAuthorized() {
        WebClient restTemplate = mock(WebClient.class);

        when(restTemplate.postForObject(isA(String.class), isA(Map.class), any())).thenReturn(new OpaClient.OpaResponse("false"));

        OpaClient opaClient = new OpaClient().setWebClient(restTemplate);
        opaClient = opaClient.setOpaUrl("http://dummy.url/");
        boolean isAuthorized = opaClient.isAuthorized("unknown@viken.no", "GET");

        assertThat(isAuthorized).isFalse();

        verify(restTemplate).postForObject(isA(String.class), isA(Map.class), any());
    }

    @Test
    public void shouldGetScopesForAuthorizedUser() {
        String opaUrl = "http://dummy.url";
        String userName = "ragnild.hansen@viken.no";

        WebClient restTemplate = mock(WebClient.class);
        Authentication authentication = mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn(userName);

        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        SecurityContextHolder.setContext(securityContext);

        Map<Object, Object> request = new HashMap<>();
        request.put("input", new OpaClient.OpaRequest(userName));

        when(restTemplate.postForObject(opaUrl + "/scopes", request, String.class)).thenReturn("""
                                                                                                       [
                                                                                                           1,
                                                                                                           2,
                                                                                                           3,
                                                                                                           4
                                                                                                       ]
                                                                                                       """);

        OpaClient opaClient = new OpaClient().setWebClient(restTemplate);
        opaClient = opaClient.setOpaUrl(opaUrl);
        String userScopes = opaClient.getUserScopes();

        assertThat(userScopes).isNotEmpty();
        assertThat(userScopes).isEqualTo("""
                                                 [
                                                     1,
                                                     2,
                                                     3,
                                                     4
                                                 ]
                                                 """);

        verify(restTemplate).postForObject(opaUrl + "/scopes", request, String.class);
    }*/


}
