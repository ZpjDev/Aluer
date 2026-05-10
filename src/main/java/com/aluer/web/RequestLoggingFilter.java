package com.aluer.web;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class RequestLoggingFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(RequestLoggingFilter.class);

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        long start = System.currentTimeMillis();

        try {
            chain.doFilter(request, response);
        } finally {
            long duration = System.currentTimeMillis() - start;
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            int status = httpResponse.getStatus();

            if (status >= 400 || duration > 1000) {
                logger.debug("{} {} → {} ({}ms)", httpRequest.getMethod(), httpRequest.getRequestURI(), status, duration);
            }

            if (status >= 500) {
                logger.warn("Server error: {} {} → {} ({}ms)", httpRequest.getMethod(), httpRequest.getRequestURI(), status, duration);
            }
        }
    }
}
