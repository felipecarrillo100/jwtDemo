package com.luciad.jwtdemo.services.security;

import io.jsonwebtoken.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private final String HEADER = "Authorization";
    private final String PREFIX = "Bearer ";
    private final String SECRET = "mySecretKey";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
            if (checkJWTToken(request, response)) {
                try {
                    Claims claims = validateToken(request);
                    if (claims.get("authorities") != null) {
                        setUpSpringAuthentication(claims);
                    } else {
                        SecurityContextHolder.clearContext();
                    }
                } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException e) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
                    return;
                }
            } else {
                    String jwt = JWTTools.getTokenFromCookies(request);
                  //  String path = request.getRequestURI().substring(request.getContextPath().length());
                    if (jwt == null) {
                        SecurityContextHolder.clearContext();
                    } else {
                        try {
                            Claims claims = JWTTools.validateTokenFromString(SECRET, jwt);
                            if (claims.get("authorities") != null) {
                                JWTTools.extendCookie(SECRET, request, response);
                                setUpSpringAuthentication(claims);
                            } else {
                                SecurityContextHolder.clearContext();
                            }
                        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException err) {
                            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                            ((HttpServletResponse) response).sendError(HttpServletResponse.SC_FORBIDDEN, err.getMessage());
                            return;
                        }
                    }
            }
            chain.doFilter(request, response);
    }

    private Claims validateToken(HttpServletRequest request) {
        String jwtToken = request.getHeader(HEADER).replace(PREFIX, "");
        return Jwts.parser().setSigningKey(SECRET.getBytes()).parseClaimsJws(jwtToken).getBody();
    }



    /**
     * Authentication method in Spring flow
     *
     * @param claims
     */
    private void setUpSpringAuthentication(Claims claims) {
        @SuppressWarnings("unchecked")
        List<String> authorities = (List) claims.get("authorities");

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), null,
                authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        SecurityContextHolder.getContext().setAuthentication(auth);

    }

    private boolean checkJWTToken(HttpServletRequest request, HttpServletResponse res) {
        String authenticationHeader = request.getHeader(HEADER);
        if (authenticationHeader == null || !authenticationHeader.startsWith(PREFIX))
            return false;
        return true;
    }

}