package no.fintlabs.securityconfig;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import no.fintlabs.exception.ErrorResponse;
import no.fintlabs.exception.ErrorResponseFactory;
import no.fintlabs.exception.JsonErrorResponseWriter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ErrorResponseFactory errorResponseFactory;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        ErrorResponse errorResponse = errorResponseFactory.create(HttpServletResponse.SC_UNAUTHORIZED,
                "Unauthorized", authException.getMessage(), request.getRequestURI());
        JsonErrorResponseWriter.write(response, errorResponse);
    }
}
