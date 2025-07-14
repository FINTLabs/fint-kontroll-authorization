package no.fintlabs.exception;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import java.io.IOException;

@Slf4j
public class JsonErrorResponseWriter {

    public static void write(HttpServletResponse response, ErrorResponse errorResponse) throws IOException {
        response.setStatus(errorResponse.status());
        response.setContentType("application/json");

        String json = """
            {
              "status": %d,
              "error": "%s",
              "message": "%s",
              "path": "%s",
              "application": "%s"
            }
            """.formatted(errorResponse.status(), errorResponse.error(), errorResponse.message(), errorResponse.path(), errorResponse.application());

        log.warn("Returning error response: {}", json);

        response.getWriter().write(json);
    }
}
