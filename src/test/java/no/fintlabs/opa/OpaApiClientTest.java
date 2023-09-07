package no.fintlabs.opa;

import no.fintlabs.opa.model.Scope;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class OpaApiClientTest {

    private MockWebServer mockWebServer;
    private OpaApiClient opaApiClient;

    @BeforeEach
    public void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setUriTemplateHandler(new DefaultUriBuilderFactory(mockWebServer.url("/").toString()));
        opaApiClient = new OpaApiClient(restTemplate);
    }

    @AfterEach
    public void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    public void testGetScopesForUser() throws InterruptedException {
        String scopesResultJson = """
                 {
                    "result": [
                        {
                            "id": "1",
                            "objecttype": "user",
                            "orgunits": [
                                "198",
                                "2",
                                "3"
                            ]
                        },
                        {
                            "id": "2",
                            "objecttype": "role",
                            "orgunits": [
                                "198",
                                "2",
                                "3"
                            ]
                        },
                        {
                            "id": "3",
                            "objecttype": "resource",
                            "orgunits": [
                                "198",
                                "2",
                                "3"
                            ]
                        }
                    ]
                }""";
        mockWebServer.enqueue(new MockResponse()
                                      .setBody(scopesResultJson)
                                      .addHeader("Content-Type", "application/json"));

        List<Scope> scopes = opaApiClient.getScopesForUser("john");

        assertEquals(3, scopes.size());
        assertEquals("1", scopes.get(0).getId());
        assertEquals("user", scopes.get(0).getObjectType());
        assertEquals(3, scopes.get(0).getOrgUnits().size());
        assertEquals("198", scopes.get(0).getOrgUnits().get(0));
        assertEquals("2", scopes.get(0).getOrgUnits().get(1));
        assertEquals("3", scopes.get(0).getOrgUnits().get(2));

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertEquals("POST", recordedRequest.getMethod());
        assertEquals("/scopes", recordedRequest.getPath());
    }

    @Test
    public void testHasUserAuthorization() throws InterruptedException {
        String isAllowed = """
                        {
                           "result": true
                        }
                """;

        mockWebServer.enqueue(new MockResponse().setBody(isAllowed)
                                      .addHeader("Content-Type", "application/json"));

        boolean isAuthorized = opaApiClient.hasUserAuthorization("john", "GET");

        assertTrue(isAuthorized);

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertEquals("POST", recordedRequest.getMethod());
        assertEquals("/allow", recordedRequest.getPath());
    }
}
