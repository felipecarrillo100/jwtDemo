package com.luciad.jwtdemo.services.security;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@RestController
public class UserController {
    String secretKey = "mySecretKey";

    @PostMapping("user")
    public User login(@RequestParam("user") String username, @RequestParam("password") String pwd, HttpServletResponse response) {
        String token = JWTTools.getJWTToken("Hexagon", secretKey, username);
        User user = new User();
        user.setUser(username);
        user.setToken(token);
        user.setPwd(null);

        // create a cookie
        JWTTools.setCookie(response, token);
        return user;
    }

    @GetMapping("/secured/token")
    public User token(HttpServletRequest request) {
        String jwt = JWTTools.getTokenFromCookies(request);
        Claims claims = JWTTools.validateTokenFromString(secretKey, jwt);
        String token = "Bearer " + jwt;
        User user = new User();
        user.setUser(claims.getSubject());
        user.setToken(token);
        user.setPwd(null);
        return user;
    }



}
