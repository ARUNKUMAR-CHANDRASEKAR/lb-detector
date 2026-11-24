package com.practise.lbdetector.security;

import com.practise.lbdetector.config.LbDetectorProperties;
import org.springframework.stereotype.Component;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * SSRF protection. A scanner exposed as a web service would otherwise let any caller make the
 * server probe internal hosts (cloud metadata at 169.254.169.254, admin consoles on 10.x, ...).
 *
 * <p>Rejects targets that resolve to loopback, private, link-local, CGNAT, multicast or
 * unspecified addresses unless {@code lbdetector.allow-private-targets=true}.
 *
 * <p>Limitation: the prober resolves the name again later, so a hostile DNS server could answer
 * differently the second time (DNS rebinding). Run the service with egress firewall rules if it
 * is exposed to untrusted users.
 */
@Component
public class TargetGuard {

    private final LbDetectorProperties props;

    public TargetGuard(LbDetectorProperties props) {
        this.props = props;
    }

    public URI validate(String rawTarget) {
        URI uri;
        try {
            uri = URI.create(rawTarget.strip());
        } catch (IllegalArgumentException e) {
            throw new InvalidTargetException("Not a valid URL: " + rawTarget);
        }
        if (uri.getScheme() == null || !(uri.getScheme().equalsIgnoreCase("http") || uri.getScheme().equalsIgnoreCase("https"))) {
            throw new InvalidTargetException("Target must start with http:// or https://");
        }
        if (uri.getHost() == null) {
            throw new InvalidTargetException("Target has no host: " + rawTarget);
        }
        if (uri.getUserInfo() != null) {
            throw new InvalidTargetException("Credentials in the URL are not allowed");
        }
        if (props.allowPrivateTargets()) {
            return uri;
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(uri.getHost());
        } catch (UnknownHostException e) {
            throw new InvalidTargetException("Host cannot be resolved: " + uri.getHost());
        }
        for (InetAddress address : addresses) {
            if (isInternal(address)) {
                throw new InvalidTargetException("Target resolves to a non-public address (" + address.getHostAddress()
                        + "). Set lbdetector.allow-private-targets=true to scan internal hosts.");
            }
        }
        return uri;
    }

    static boolean isInternal(InetAddress a) {
        if (a.isLoopbackAddress() || a.isAnyLocalAddress() || a.isLinkLocalAddress()
                || a.isSiteLocalAddress() || a.isMulticastAddress()) {
            return true;
        }
        byte[] b = a.getAddress();
        if (a instanceof Inet6Address) {
            return (b[0] & 0xFE) == 0xFC; // fc00::/7 unique local
        }
        return (b[0] & 0xFF) == 100 && (b[1] & 0xC0) == 64; // 100.64.0.0/10 carrier-grade NAT
    }
}
