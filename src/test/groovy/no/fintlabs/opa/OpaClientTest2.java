package no.fintlabs.opa;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OpaClientTest2 {

    /*private MockWebServer mockWebServer;
    private OpaClient opaClient;

    @BeforeEach
    void setUp() throws Exception {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        *//*opaClient = new OpaClient();
        opaClient.setOpaUrl(mockWebServer.url("/").toString());
        opaClient.setWebClient(WebClient.create(mockWebServer.url("/").toString()));*//*
    }

    @AfterEach
    void tearDown() throws Exception {
        mockWebServer.shutdown();
    }

    @Test
    void testIsAuthorized() {
        // Given
        mockWebServer.enqueue(new MockResponse()
                                      .setBody("{\"result\": \"true\"}")
                                      .addHeader("Content-Type", "application/json"));

        // When
        Mono<Boolean> result = opaClient.isAuthorized("testUser", "testOp");

        // Then
        StepVerifier.create(result)
                .expectNext(true)
                .verifyComplete();
    }*/

    /*@Test
    void testGetUserScopes() {
        // Assuming authenticated: Here, you should also mock the authentication flow.
        // This is just a basic example.
        ReactiveSecurityContextHolder securityContext = mock(ReactiveSecurityContextHolder.class);
        SecurityContext context = mock(SecurityContext.class);
        when(securityContext.getContext()).thenReturn(Mono.just(context));
        Authentication authentication = mock(Authentication.class);
        when(authentication.isAuthenticated()).thenReturn(true);
        when(ReactiveSecurityContextHolder.getContext()).thenReturn(authentication);

        SecurityContextHolder.setContext(securityContext);

        mockWebServer.enqueue(new MockResponse()
                                      .setBody("\"testScope\"")
                                      .addHeader("Content-Type", "application/json"));

        // When
        Mono<String> result = opaClient.getUserScopes();

        // Then
        StepVerifier.create(result)
                .expectNext("testScope")
                .verifyComplete();
    }*/
}
