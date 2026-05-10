package com.aluer.security;

import com.aluer.console.AluerMirageShieldService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class WafRequestFilter extends OncePerRequestFilter {
    private final WebApplicationFirewall webApplicationFirewall;
    private final AluerMirageShieldService aluerMirageShieldService;

    public WafRequestFilter(WebApplicationFirewall webApplicationFirewall,
                            AluerMirageShieldService aluerMirageShieldService) {
        this.webApplicationFirewall = webApplicationFirewall;
        this.aluerMirageShieldService = aluerMirageShieldService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return uri.startsWith("/favicon")
            || uri.startsWith("/assets/")
            || uri.endsWith(".css")
            || uri.endsWith(".js")
            || uri.endsWith(".png")
            || uri.endsWith(".ico");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Map<String, String> headers = extractHeaders(request);
        String clientIp = resolveClientIp(request);
        WebApplicationFirewall.WAFResult result = webApplicationFirewall.checkRequest(
            clientIp,
            request.getMethod(),
            request.getRequestURI(),
            request.getQueryString(),
            headers,
            null
        );

        if (result.isBlocked()) {
            String notice = aluerMirageShieldService.composeDeterrenceNotice(clientIp, result.getReason());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json");
            response.setHeader("X-Aluer-Deterrence", "identified-and-isolated");
            response.getWriter().write(
                "{\"status\":\"blocked\",\"reason\":\"" + escapeJson(result.getReason()) +
                    "\",\"source\":\"" + escapeJson(clientIp) +
                    "\",\"notice\":\"" + escapeJson(notice) + "\"}"
            );
            return;
        }

        request.setAttribute("aluer.waf.suspicious", result.isSuspicious());
        request.setAttribute("aluer.waf.rules", result.getMatchedRules());
        filterChain.doFilter(request, response);
    }

    private Map<String, String> extractHeaders(HttpServletRequest request) {
        Map<String, String> headers = new LinkedHashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        if (names == null) {
            return Collections.emptyMap();
        }
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            headers.put(name, request.getHeader(name));
        }
        return headers;
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
