package no.fintlabs.opa;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import java.util.LinkedHashMap;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class OpaApiClientTest {

    private MockWebServer mockWebServer;
    private OpaApiClient opaApiClient;

    @BeforeEach
    void setUp() throws Exception {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        WebClient.Builder webClientBuilder = WebClient.builder().baseUrl(mockWebServer.url("/").toString());
        opaApiClient = new OpaApiClient(webClientBuilder);
    }

    @AfterEach
    void tearDown() throws Exception {
        mockWebServer.shutdown();
    }

    @Test
    public void testGetScopesForUser() throws InterruptedException {
        String user = "testUser";
        LinkedHashMap<String, Object> result = new LinkedHashMap<>();

        LinkedHashMap<String, Object> scopes = new LinkedHashMap<>();
        scopes.put("scope", "value");

        result.put("result", scopes);

        // Mock a server response
        mockWebServer
                .enqueue(new MockResponse()
                                 .addHeader("Content-Type", "application/json")
                                 .setResponseCode(200).setBody("{\"result\": {\"scope\": \"value\"}}"));

        StepVerifier.create(opaApiClient.getScopesForUser(user))
                .expectNext(result)
                .verifyComplete();

        // Verify that the server received a POST request to "/scopes"
        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertEquals("POST", recordedRequest.getMethod());
        assertEquals("/scopes", recordedRequest.getPath());
    }
}
