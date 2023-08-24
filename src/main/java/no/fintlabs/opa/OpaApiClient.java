package no.fintlabs.opa;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON;

@Slf4j
@Component
public class OpaApiClient {
    private final WebClient webClient;

    public OpaApiClient(WebClient.Builder webClientBuilder) {
        this.webClient = webClientBuilder.build();
    }

    public Mono<LinkedHashMap> getScopesForUser(String user) {
        log.info("Getting scopes for user {}", user);

        return webClient.post()
                .uri("/scopes")
                .contentType(APPLICATION_JSON)
                .bodyValue(createOpaRequestData(user, "GET"))
                .retrieve()
                .bodyToMono(LinkedHashMap.class)
                .map(map -> {
                    log.info("Got scopes from OPA: {}", map);
                    return map;
                })
                .log()
                .doOnError(throwable -> log.error("Error getting scopes from OPA", throwable))
                .onErrorResume(throwable -> Mono.just(new LinkedHashMap()));
    }

    public Mono<Boolean> hasUserAuthorization(String user, String operation) {
        return webClient.post()
                .uri("/allow")
                .bodyValue(createOpaRequestData(user, operation))
                .retrieve()
                .bodyToMono(OpaResponse.class)
                .map(opaResponse -> {
                    log.info("User {} got authorization response for operation {}: {}", user, operation, opaResponse.result());
                    return authorized(opaResponse);
                })
                .log()
                .doOnError(throwable -> log.error("Error checking authorization in OPA", throwable))
                .onErrorResume(throwable -> Mono.just(false));
    }

    private static Map<String, Object> createOpaRequestData(String user, String operation) {
        return Map.of("input", new OpaRequest(user, operation));
    }

    private static Map<String, Object> createOpaRequestData(String user) {
        return Map.of("input", new OpaRequest(user));
    }

    private static boolean authorized(OpaResponse opaResponse) {
        return opaResponse.result() != null && opaResponse.result().equals("true");
    }

    record OpaRequest(String user, String operation) {
        public OpaRequest(String user) {
            this(user, null);
        }
    }

    protected record OpaResponse(String result) {
    }
}
