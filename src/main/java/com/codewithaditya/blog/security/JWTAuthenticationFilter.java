package com.codewithaditya.blog.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JWTTokenHelper jwtTokenHelper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //1. get token
        String requestToken = request.getHeader("Authorization");

        //Bearer 12312321ssdh21 - token will come in encrypted format
        System.out.println(requestToken);

        String username = null;
        String token = null;

        if (requestToken!=null && requestToken.startsWith("Bearer")){

            token = requestToken.substring(7);

            try {
                username = this.jwtTokenHelper.getUsernameFromToken(token);

            }catch (IllegalArgumentException e){
                System.out.println("Unable to get JWT token");
            }catch (ExpiredJwtException e){
                System.out.println("JWT token has Expired !");
            }catch (MalformedJwtException e){
                System.out.println("Invalid JWT");
            }
        }else {
            System.out.println("Jwt token does not begin with Bearer");
        }

        // once we get the token, now validate
        //2. Validate

        if (username!=null && SecurityContextHolder.getContext().getAuthentication()==null){

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            if (this.jwtTokenHelper.validateToken(token, userDetails)){
                //sb sahi chl rha h
                //authentication karna h ab
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

            }else {
                System.out.println("Invalid Jwt token");
            }

        }else {
            System.out.println("Username is null or context is not null");
        }

        filterChain.doFilter(request, response);
    }
}
