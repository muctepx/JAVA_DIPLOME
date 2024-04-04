package com.example.diplome.service;

import com.example.diplome.entity.Device;
import com.example.diplome.entity.User;

import java.util.List;


public interface DeviceService {
    Device get(Long id);
    Device get(String number);
    List<Device> getAll();
    List<Device> findAllByUser(User user);
    void create(Device device);
}
