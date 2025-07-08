package no.fintlabs.securityconfig;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import no.fintlabs.util.JsonErrorResponseWriter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Value("${fint.application-id}")
    private String applicationId;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        JsonErrorResponseWriter.write(
                response,
                HttpServletResponse.SC_FORBIDDEN,
                "Access-denied",
                accessDeniedException.getMessage(),
                request.getRequestURI(),
                applicationId
        );
    }
}
