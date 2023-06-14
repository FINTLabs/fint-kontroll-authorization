package no.fintlabs.opa;

import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class OpaClientTest {
    @Test
    public void shouldBeAuthorized() {
        RestTemplate restTemplate = mock(RestTemplate.class);

        when(restTemplate.postForObject(isA(String.class), isA(Map.class), any())).thenReturn(new OpaClient.OpaResponse("true"));

        OpaClient opaClient = new OpaClient().setRestTemplate(restTemplate);
        boolean isAuthorized = opaClient.isAuthorized("ragnild.hansen@viken.no", "GET");

        assertThat(isAuthorized).isTrue();

        verify(restTemplate).postForObject(isA(String.class), isA(Map.class), any());
    }

    @Test
    public void unknownUserShouldNotBeAuthorized() {
        RestTemplate restTemplate = mock(RestTemplate.class);

        when(restTemplate.postForObject(isA(String.class), isA(Map.class), any())).thenReturn(new OpaClient.OpaResponse("false"));

        OpaClient opaClient = new OpaClient().setRestTemplate(restTemplate);
        boolean isAuthorized = opaClient.isAuthorized("unknown@viken.no", "GET");

        assertThat(isAuthorized).isFalse();

        verify(restTemplate).postForObject(isA(String.class), isA(Map.class), any());
    }
}
