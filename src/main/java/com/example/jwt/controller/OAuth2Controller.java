package com.example.jwt.controller;

import com.example.jwt.config.oauth.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
public class OAuth2Controller {


    @GetMapping("/oauth2/callback/{provider}")
    public String login(@PathVariable String provider, @RequestParam String code) {
        System.out.println(code);
        System.out.println(provider);
        return "test";
    }
    @GetMapping(value = "/auth/token")
    public String token(@RequestParam String token, @RequestParam String error) {
        if (StringUtils.isNotBlank(error)) {
            return error;
        } else {
            return token;
        }
    }

}
