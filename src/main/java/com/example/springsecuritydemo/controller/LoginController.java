package com.example.springsecuritydemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @GetMapping("/login/sendOtp")
    public String sendOtp() {
        return "OTP sent successfully for the given mobile number.";
    }

    @GetMapping("/login/verifyOtp")
    public String verifyOtp() {
        return "OTP verified successfully.";
    }

}
