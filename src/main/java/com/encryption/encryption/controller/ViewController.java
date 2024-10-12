package com.encryption.encryption.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {

    @GetMapping("/aes")
    public String aes() {
        return "aes";
    }

    @GetMapping("/rsa")
    public String rsa() {
        return "rsa";
    }
}
