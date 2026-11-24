package com.practise.lbdetector.api;

import com.practise.lbdetector.security.InvalidTargetException;
import com.practise.lbdetector.service.TooManyScansException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;

/**
 * Maps errors to RFC 9457 Problem Details ({@code application/problem+json}).
 * Validation errors are handled by the inherited {@link ResponseEntityExceptionHandler}.
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(InvalidTargetException.class)
    ProblemDetail invalidTarget(InvalidTargetException e) {
        return problem(HttpStatus.BAD_REQUEST, "invalid-target", "Invalid target", e.getMessage());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail badArgument(IllegalArgumentException e) {
        return problem(HttpStatus.BAD_REQUEST, "invalid-request", "Invalid request", e.getMessage());
    }

    @ExceptionHandler(TooManyScansException.class)
    ProblemDetail busy(TooManyScansException e) {
        return problem(HttpStatus.TOO_MANY_REQUESTS, "too-many-scans", "Too many scans", e.getMessage());
    }

    private static ProblemDetail problem(HttpStatus status, String type, String title, String detail) {
        var pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setType(URI.create("urn:lb-detector:problem:" + type));
        pd.setTitle(title);
        return pd;
    }
}
