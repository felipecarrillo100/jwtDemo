package com.luciad.jwtdemo.services.security;

import io.jsonwebtoken.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JWTTools {
    // public static int TimeToLive = 600000;
    public static int TimeToLive = 600000;
    public static String getTokenFromCookies(HttpServletRequest request) {
        String jwtToken = null;
        Cookie[] cookies = ((HttpServletRequest) request).getCookies();
        if (cookies != null) {
            for (Cookie ck : cookies) {
                if(ck.getName().toString().equals("JWTSESSION")){
                    jwtToken = ck.getValue();
                }
            }
        }
        return jwtToken;
    }

    public static Claims validateTokenFromString(String SECRET, String jwtToken) {
        return Jwts.parser().setSigningKey(SECRET.getBytes()).parseClaimsJws(jwtToken).getBody();
    }

    public static String getJWTToken(String Issuer, String SECRET, String username) {
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils
                .commaSeparatedStringToAuthorityList("ROLE_USER");

        String token = Jwts
                .builder()
                .setId(Issuer)
                .setSubject(username)
                .claim("authorities",
                        grantedAuthorities.stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList()))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeToLive))
                .signWith(SignatureAlgorithm.HS512, SECRET.getBytes()).compact();

        return "Bearer " + token;
    }

    public static void setCookie(HttpServletResponse response, String token) {
        String tk = token.substring("Bearer ".length());
        Cookie cookie = new Cookie("JWTSESSION", tk);
        cookie.setPath("/secured");
        //add cookie to response
        response.addCookie(cookie);
    }

    public static void extendCookie(String SECRET, HttpServletRequest request, HttpServletResponse response) {
        String oldToken = getTokenFromCookies(request);
        String newToken = extendToken(SECRET, oldToken);
        setCookie(response, newToken);
    }

    public static String extendToken(String SECRET, String oldToken) {
    //    String tk = oldToken.substring("Bearer ".length());
        Claims claims = JWTTools.validateTokenFromString(SECRET, oldToken);
        try {
            Object authorities = claims.get("authorities");
            String token = Jwts
                    .builder()
                    .setId(claims.getIssuer())
                    .setSubject(claims.getSubject())
                    .claim("authorities", authorities)
                    .setIssuedAt(new Date(System.currentTimeMillis()))
                    .setExpiration(new Date(System.currentTimeMillis() + TimeToLive))
                    .signWith(SignatureAlgorithm.HS512, SECRET.getBytes()).compact();
            return "Bearer " + token;
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException e) {
            return oldToken;
        }
    }

    public static void clearCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("JWTSESSION", "");
        cookie.setPath("/secured");
        cookie.setMaxAge(0);
        //add cookie to response
        response.addCookie(cookie);
    }
}
