package no.fintlabs.opa;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import no.fintlabs.opa.model.AllowResponse;
import no.fintlabs.opa.model.OpaRequest;
import no.fintlabs.opa.model.RolesResponse;
import no.fintlabs.opa.model.Scope;
import no.fintlabs.opa.model.ScopesListResponse;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;


@Slf4j
@Component
public class OpaApiClient {

    private RestTemplate restTemplate;

    public OpaApiClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public List<Scope> getScopesListForUser(String user, String url) {
        log.info("Getting scopes for user {}", user);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(createOpaRequestData(user, "GET", url), headers);

        try {
            ResponseEntity<ScopesListResponse> response = restTemplate.exchange("/scopeslist", HttpMethod.POST, request, ScopesListResponse.class);
            log.info("Got scopes from OPA: {}", response.getBody());

            List<Scope> flattenedScopes = response.getBody().getScopes().stream()
                    .flatMap(List::stream)
                    .toList();

            Map<String, Set<String>> groupedScopes = new HashMap<>();
            for (Scope scope : flattenedScopes) {
                groupedScopes.computeIfAbsent(scope.getObjectType(), k -> new HashSet<>()).addAll(scope.getOrgUnits());
            }

            List<Scope> mergedScopes = new ArrayList<>();
            for (Map.Entry<String, Set<String>> entry : groupedScopes.entrySet()) {
                mergedScopes.add(new Scope(entry.getKey(), new ArrayList<>(entry.getValue())));
            }

            return mergedScopes;
        } catch (HttpClientErrorException e) {
            log.warn("Could not fetch scopes for user {}. Response status: {}", user, e.getStatusCode());
        } catch (Exception e) {
            log.error("An error occurred while fetching scopes for user {}", user, e);
        }

        return Collections.emptyList();
    }

    public boolean hasUserAuthorization(String user, String operation, String url) {
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(createOpaRequestData(user, operation, url));

        try {
            log.info("Fetching authorization for user {}, operation {} and url {}", user, operation, url);
            ResponseEntity<AllowResponse> allow = restTemplate.exchange("/allow", HttpMethod.POST, request, AllowResponse.class);

            boolean authorized = allow.getBody() != null && allow.getBody().isAllow();
            log.info("User {} got authorization response for operation {}: {}", user, operation, authorized);

            return authorized;
        } catch (HttpClientErrorException e) {
            log.warn("Could not fetch authorization for user {}. Response status: {}", user, e.getStatusCode());
        } catch (Exception e) {
            log.error("An error occurred while fetching authorization for user {}", user, e);
        }

        return false;
    }

    private Map<String, Object> createOpaRequestData(String user, String operation, String url) {
        return Map.of("input", new OpaRequest(user, operation, url));
    }

    private String getRequestURI() {
        if (RequestContextHolder.getRequestAttributes() == null) {
            return "";
        }

        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        return request.getRequestURI();
    }

    public List<String> getRolesForUser(String userName) {
        log.info("Getting roles for user {}", userName);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, Object>> request = new HttpEntity<>(createOpaRequestData(userName, "GET", getRequestURI()), headers);

        try {
            ResponseEntity<RolesResponse> response = restTemplate.exchange("/roles", HttpMethod.POST, request, RolesResponse.class);
            log.info("Got user assignments from OPA: {}", response.getBody());

            if (response.getBody() != null) {
                return response.getBody().getRoles().stream()
                        .flatMap(List::stream)
                        .toList();
            }
        } catch (HttpClientErrorException e) {
            log.warn("Could not fetch roles for user {}. Response status: {}", userName, e.getStatusCode());
        } catch (Exception e) {
            log.error("An error occurred while fetching roles for user {}", userName, e);
        }

        return Collections.emptyList();
    }




}
