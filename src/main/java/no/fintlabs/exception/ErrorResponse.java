package no.fintlabs.exception;

public record ErrorResponse(
        int status,
        String error,
        String message,
        String path,
        String application
) {
}
