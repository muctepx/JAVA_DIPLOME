package com.example.diplome.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.diplome.entity.Data;

public interface DataRepository extends JpaRepository<Data, Long> {
}
