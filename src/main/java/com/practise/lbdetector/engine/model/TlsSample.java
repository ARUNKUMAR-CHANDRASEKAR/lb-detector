package com.practise.lbdetector.engine.model;

/**
 * Certificate and handshake details from one fresh TLS connection (no session resumption).
 */
public record TlsSample(int index, String subject, String issuer, String serialNumber,
                        String sha256Fingerprint, String protocol, String cipherSuite) {
}
