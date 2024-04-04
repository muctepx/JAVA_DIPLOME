package com.example.diplome.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import com.example.diplome.entity.Role;
import com.example.diplome.entity.User;
import com.example.diplome.repository.RoleRepository;
import com.example.diplome.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.*;

@Service
public class UserService implements UserDetailsService {
    @PersistenceContext
    private EntityManager em;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;
//    @Autowired
//    PasswordEncoder bCryptPasswordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }

        return user;
    }

    public User findUserById(Long userId) {
        Optional<User> userFromDb = userRepository.findById(userId);
        return userFromDb.orElse(new User());
    }
    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public List<User> allUsers() {
        return userRepository.findAll();
    }

    public boolean saveUser(User user) {
        User userFromDB = userRepository.findByUsername(user.getUsername());

        if (userFromDB != null) {
            return false;
        }
        if (userRepository.count() == 0){
            user.setRoles(new HashSet<Role>(Arrays.asList(
                    new Role(1L, "ROLE_ADMIN"),
                    new Role(2L, "ROLE_USER"))));
        }
        else {
            user.setRoles(Collections.singleton(new Role(2L, "ROLE_USER")));
        }
        roleRepository.saveAll(user.getRoles());
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return true;
    }

    public boolean deleteUser(Long userId) {
        if (userRepository.findById(userId).isPresent()
                && !userRepository.findById(userId).get().getRoles().stream().anyMatch(
                role -> role.getName().equals("ROLE_ADMIN"))) {
            userRepository.deleteById(userId);
            return true;
        }
        return false;
    }

    public List<User> usergtList(Long idMin) {
        return em.createQuery("SELECT u FROM User u WHERE u.id > :paramId", User.class)
                .setParameter("paramId", idMin).getResultList();
    }
}
