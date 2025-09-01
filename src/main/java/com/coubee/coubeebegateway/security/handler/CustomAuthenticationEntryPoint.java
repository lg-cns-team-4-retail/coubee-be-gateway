package com.coubee.coubeebegateway.security.handler;

import com.coubee.coubeebegateway.common.dto.ApiResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {
        String originalUri = (String) request.getAttribute(RequestDispatcher.FORWARD_REQUEST_URI);
        String currentUri = request.getRequestURI();

        log.info("=== 인증 실패 ===");
        log.info("현재 URI: {}", currentUri);
        log.info("원래 URI: {}", originalUri);
        log.info("요청 메서드: {}", request.getMethod());
        log.info("User-Agent: {}", request.getHeader("User-Agent"));
        log.info("실패 이유: {}", authException.getMessage());
        log.info("예외 타입: {}", authException.getClass().getSimpleName());
        log.info("이유: {}",authException.getMessage());
        ApiResponseDto<String> error = ApiResponseDto.createError(
                "UNAUTHORIZED", "인증이 필요합니다.");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(error));
    }
}