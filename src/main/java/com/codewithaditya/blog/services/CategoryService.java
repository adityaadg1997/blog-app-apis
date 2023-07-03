package com.codewithaditya.blog.services;

import com.codewithaditya.blog.payloads.CategoryDto;

import java.util.List;

public interface CategoryService {

    //create
    CategoryDto createCategory(CategoryDto categoryDto);

    //read by id
    CategoryDto getCategoryById(Integer categoryId);

    //read all
    List<CategoryDto> getCategories();

    //update by id
    CategoryDto updateCategory(Integer categoryId, CategoryDto categoryDto);

    //delete by id
    void deleteCategory(Integer categoryId);
}
