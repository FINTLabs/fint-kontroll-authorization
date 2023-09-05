package no.fintlabs.opa;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.Map;


@Slf4j
@Component
public class OpaApiClientSync {

    private RestTemplate restTemplate;

    public OpaApiClientSync(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public LinkedHashMap getScopesForUser(String user) {
        log.info("Getting scopes for user {}", user);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(createOpaRequestData(user, "GET"), headers);

        LinkedHashMap response = restTemplate.postForObject("/scopes", request, LinkedHashMap.class);
        log.info("Got scopes from OPA: {}", response);

        return response != null ? response : new LinkedHashMap();
    }

    public boolean hasUserAuthorization(String user, String operation) {
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(createOpaRequestData(user, operation));
        log.info("url: " + restTemplate.getUriTemplateHandler().expand("/allow"));
        LinkedHashMap response = restTemplate.postForObject("/allow", request, LinkedHashMap.class);

        boolean authorized = response != null && response.get("result") != null && response.get("result").equals(true);

        log.info("User {} got authorization response for operation {}: {}", user, operation, authorized);

        return authorized;
    }

    private Map<String, Object> createOpaRequestData(String user, String operation) {
        return Map.of("input", new OpaRequest(user, operation));
    }

}
