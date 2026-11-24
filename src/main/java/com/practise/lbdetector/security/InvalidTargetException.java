package com.practise.lbdetector.security;

/** The requested target is malformed or not allowed. Mapped to HTTP 400. */
public class InvalidTargetException extends RuntimeException {

    public InvalidTargetException(String message) {
        super(message);
    }
}
