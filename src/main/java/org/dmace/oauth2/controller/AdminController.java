package org.dmace.oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.Objects;

@Controller
public class AdminController {

    @GetMapping("/admin")
    public String getIndexPage(Model model, Authentication authentication) {
        if (Objects.nonNull(authentication) && authentication.isAuthenticated()) {
            if (authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ADMIN"))) {
                model.addAttribute("secretMessage", "Admin message is s3crEt");
            } else {
                model.addAttribute("secretMessage", "Lorem ipsum dolor sit amet");
            }
        }

        model.addAttribute("message", "AWS Cognito with Spring Security");

        return "admin/home";
    }
}