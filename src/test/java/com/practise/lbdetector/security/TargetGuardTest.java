package com.practise.lbdetector.security;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;

class TargetGuardTest {

    @ParameterizedTest
    @ValueSource(strings = {"127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254",
            "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1"})
    void internalAddressesAreBlocked(String ip) throws Exception {
        assertThat(TargetGuard.isInternal(InetAddress.getByName(ip))).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"8.8.8.8", "1.1.1.1", "203.0.113.10", "2606:4700:4700::1111"})
    void publicAddressesAreAllowed(String ip) throws Exception {
        assertThat(TargetGuard.isInternal(InetAddress.getByName(ip))).isFalse();
    }
}
