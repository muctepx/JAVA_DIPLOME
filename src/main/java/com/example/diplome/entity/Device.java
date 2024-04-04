package com.example.diplome.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "t_devices")
@Getter
@Setter
@EqualsAndHashCode(of = "id")
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "ID", updatable = false, nullable = false)
    private Long id = null;

    @Column(name = "number")
    private String number;

    @Column(name = "name", nullable = false)
    private String name;

    @ManyToOne(cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonBackReference
    private User user;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "device", fetch = FetchType.LAZY, orphanRemoval = true)
    @JsonManagedReference
    private Set<Data> data = new HashSet<>();

    public void setDeviceData(Set<Data> data) {
        this.data.clear();
        if (data != null) {
            this.data.addAll(data);
        }
    }



}