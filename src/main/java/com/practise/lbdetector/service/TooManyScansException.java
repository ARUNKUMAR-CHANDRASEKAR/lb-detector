package com.practise.lbdetector.service;

/** The service is already running its maximum number of scans. Mapped to HTTP 429. */
public class TooManyScansException extends RuntimeException {

    public TooManyScansException(int limit) {
        super("Too many scans in progress (limit " + limit + "). Try again shortly.");
    }
}
