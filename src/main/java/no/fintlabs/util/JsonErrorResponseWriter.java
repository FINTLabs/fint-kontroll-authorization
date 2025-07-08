package no.fintlabs.util;

import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import java.io.IOException;

@Slf4j
public class JsonErrorResponseWriter {

    public static void write(HttpServletResponse response, int statusCode, String error, String message, String path, String applicationId) throws IOException {
        response.setStatus(statusCode);
        response.setContentType("application/json");

        String json = """
            {
              "status": %d,
              "error": "%s",
              "message": "%s",
              "path": "%s",
              "application": "%s"
            }
            """.formatted(statusCode, error, message, path, applicationId);

        log.warn("Returning error response: {}", json);

        response.getWriter().write(json);
    }
}
