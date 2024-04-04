package com.example.diplome.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;

@Entity
@Table(name = "t_data")
@Getter
@Setter
@EqualsAndHashCode(of = "id")
public class Data implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    private Long id = null;

    @Column(name = "data", updatable = false, nullable = false)
    private String data = null;


    @ManyToOne(fetch = FetchType.LAZY)
    @JsonBackReference
    private Device device;
}
