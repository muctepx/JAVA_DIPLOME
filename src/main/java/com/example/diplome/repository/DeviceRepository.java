package com.example.diplome.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.diplome.entity.Device;
import com.example.diplome.entity.User;

import java.util.List;


public interface DeviceRepository extends JpaRepository<Device, Long> {

    List<Device> findAllByUser(User user);
    Device findByNumber(String number);
    //void create(Device device);

}
