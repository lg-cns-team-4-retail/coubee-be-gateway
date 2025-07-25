package com.coubee.coubeebegateway.gateway.filter;

import com.coubee.coubeebegateway.common.util.HttpUtils;
import com.coubee.coubeebegateway.security.jwt.authentication.UserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.servlet.function.ServerRequest;

import java.util.function.Function;

@Slf4j
public class AuthenticationHeaderFilterFunction {
    public static Function<ServerRequest, ServerRequest> addHeader() {
        return request -> {
            ServerRequest.Builder requestBuilder = ServerRequest.from(request);

            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if( principal instanceof UserPrincipal userPrincipal) {
                requestBuilder.header("X-Auth-UserId", userPrincipal.getUserId());
                requestBuilder.header("X-Auth-UserName", userPrincipal.getUsername());
                requestBuilder.header("X-Auth-UserNickName", userPrincipal.getNickName());
                requestBuilder.header("X-Auth-Role", userPrincipal.getRole());
                log.info("role : {}",userPrincipal.getRole());
                // 필요시 권한 정보 입력
                // requestBuilder.header("X-Auth-Authorities", ...);
            }

            String remoteAddr = HttpUtils.getRemoteAddr(request.servletRequest());
            requestBuilder.header("X-Client-Address", remoteAddr);

            // org.springframework.boo:spring-boot-starter-mobile:1.5.22.RELEASE

            String device = "WEB";
            requestBuilder.header("X-Client-Device", device);

            return requestBuilder.build();
        };
    }
}
