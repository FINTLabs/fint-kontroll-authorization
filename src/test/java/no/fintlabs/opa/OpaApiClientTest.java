package no.fintlabs.opa;

import jakarta.servlet.http.HttpServletRequest;
import no.fintlabs.opa.model.Scope;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
public class OpaApiClientTest {

    private MockWebServer mockWebServer;
    private OpaApiClient opaApiClient;

    @Mock
    private HttpServletRequest httpServletRequest;

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
    public void testGetScopesForUserWhoHasMultipleRolesWithSameScopes() throws InterruptedException {
        String scopesResultJson = """
                {
                    "result": [
                        [
                            {
                                "id": "3",
                                "objecttype": "resource",
                                "orgunits": [
                                    "198",
                                    "153",
                                    "6",
                                    "1"
                                ]
                            },
                            {
                                "id": "7",
                                "objecttype": "orgunit",
                                "orgunits": [
                                    "22",
                                    "33",
                                    "44",
                                    "55"
                                ]
                            }
                        ],
                        [
                            {
                                "id": "4",
                                "objecttype": "orgunit",
                                "orgunits": [
                                    "198",
                                    "153",
                                    "6",
                                    "1"
                                ]
                            },
                            {
                                "id": "1",
                                "objecttype": "user",
                                "orgunits": [
                                    "198",
                                    "153",
                                    "6",
                                    "1"
                                ]
                            },
                            {
                                "id": "2",
                                "objecttype": "role",
                                "orgunits": [
                                    "198",
                                    "153",
                                    "6",
                                    "1"
                                ]
                            }
                        ]
                    ]
                }""";
        mockWebServer.enqueue(new MockResponse()
                                      .setBody(scopesResultJson)
                                      .addHeader("Content-Type", "application/json"));

        List<Scope> scopes = opaApiClient.getScopesListForUser("john", "/api/");

        assertEquals(4, scopes.size());
        assertEquals("role", scopes.get(0).getObjectType());
        assertEquals(4, scopes.get(0).getOrgUnits().size());
        assertEquals("198", scopes.get(0).getOrgUnits().get(0));
        assertEquals("1", scopes.get(0).getOrgUnits().get(1));
        assertEquals("6", scopes.get(0).getOrgUnits().get(2));
        assertEquals("153", scopes.get(0).getOrgUnits().get(3));

        assertEquals("resource", scopes.get(1).getObjectType());
        assertEquals(4, scopes.get(1).getOrgUnits().size());
        assertEquals("198", scopes.get(1).getOrgUnits().get(0));
        assertEquals("1", scopes.get(1).getOrgUnits().get(1));
        assertEquals("6", scopes.get(1).getOrgUnits().get(2));
        assertEquals("153", scopes.get(1).getOrgUnits().get(3));

        assertEquals("orgunit", scopes.get(2).getObjectType());
        assertEquals(8, scopes.get(2).getOrgUnits().size());
        assertEquals("22", scopes.get(2).getOrgUnits().get(0));
        assertEquals("33", scopes.get(2).getOrgUnits().get(1));
        assertEquals("44", scopes.get(2).getOrgUnits().get(2));
        assertEquals("55", scopes.get(2).getOrgUnits().get(3));
        assertEquals("198", scopes.get(2).getOrgUnits().get(4));
        assertEquals("1", scopes.get(2).getOrgUnits().get(5));
        assertEquals("6", scopes.get(2).getOrgUnits().get(6));
        assertEquals("153", scopes.get(2).getOrgUnits().get(7));

        assertEquals("user", scopes.get(3).getObjectType());
        assertEquals(4, scopes.get(3).getOrgUnits().size());
        assertEquals("198", scopes.get(3).getOrgUnits().get(0));
        assertEquals("1", scopes.get(3).getOrgUnits().get(1));
        assertEquals("6", scopes.get(3).getOrgUnits().get(2));
        assertEquals("153", scopes.get(3).getOrgUnits().get(3));

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertEquals("POST", recordedRequest.getMethod());
        assertEquals("/scopeslist", recordedRequest.getPath());
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

        boolean isAuthorized = opaApiClient.hasUserAuthorization("john", "GET", "http://localhost:8080/api/orgunits");

        assertTrue(isAuthorized);

        RecordedRequest recordedRequest = mockWebServer.takeRequest();
        assertEquals("POST", recordedRequest.getMethod());
        assertEquals("/allow", recordedRequest.getPath());
    }
}
