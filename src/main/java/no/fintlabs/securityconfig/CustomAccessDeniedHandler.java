package no.fintlabs.securityconfig;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import no.fintlabs.exception.ErrorResponse;
import no.fintlabs.exception.ErrorResponseFactory;
import no.fintlabs.exception.JsonErrorResponseWriter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ErrorResponseFactory errorResponseFactory;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
        ErrorResponse errorResponse = errorResponseFactory.create(HttpServletResponse.SC_FORBIDDEN,
                "Access-denied", accessDeniedException.getMessage(), request.getRequestURI());
        JsonErrorResponseWriter.write(response, errorResponse);
    }
}
