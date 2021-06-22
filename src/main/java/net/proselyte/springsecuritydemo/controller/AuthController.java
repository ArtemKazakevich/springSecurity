package net.proselyte.springsecuritydemo.controller;

import net.proselyte.springsecuritydemo.model.Role;
import net.proselyte.springsecuritydemo.model.Status;
import net.proselyte.springsecuritydemo.model.User;
import net.proselyte.springsecuritydemo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@Controller
@RequestMapping("/auth")
public class AuthController {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    PasswordEncoder passwordEncoder;

    @GetMapping("/login")
    public String getLoginPage() {
        return "login";
    }

    @GetMapping("/success")
    public String getSuccessPage() {
        return "success";
    }
    
    @GetMapping("/reg")
    public String getAuthorizationPage() {
        return "reg";
    }
    
    @PostMapping("/reg")
    public String addUser(User user, Map<String, Object> model) {
        Optional<User> userFromDb = userRepository.findByEmail(user.getEmail());
        
        if (userFromDb.isPresent()) {
            model.put("message", "User exists!");
            return "reg";
        }
    
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole(Role.USER);
        user.setStatus(Status.ACTIVE);
        userRepository.save(user);
    
        return "redirect:/login";
    }
}
