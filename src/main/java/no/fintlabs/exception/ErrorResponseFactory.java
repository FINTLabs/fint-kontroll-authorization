package no.fintlabs.exception;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ErrorResponseFactory {

    @Value("${fint.application-id}")
    private String applicationId;

    public ErrorResponse create(int status, String error, String message, String path) {
        return new ErrorResponse(status, error, message, path, applicationId);
    }
}
