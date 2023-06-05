package com.example.springsecuritydemo.config;

public class JwtTokenException extends RuntimeException {

    public JwtTokenException(Throwable cause) {
        super(cause);
    }
}