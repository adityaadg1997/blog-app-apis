package com.codewithaditya.blog.services.impl;

import com.codewithaditya.blog.entitiles.Category;
import com.codewithaditya.blog.exceptions.ResourceNotFoundException;
import com.codewithaditya.blog.payloads.CategoryDto;
import com.codewithaditya.blog.repositories.CategoryRepo;
import com.codewithaditya.blog.services.CategoryService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class CategoryServiceImpl implements CategoryService {

    @Autowired
    private CategoryRepo categoryRepo;

    @Autowired
    private ModelMapper modelMapper;

    @Override
    public CategoryDto createCategory(CategoryDto categoryDto) {
        Category category = this.modelMapper.map(categoryDto, Category.class);
        Category savedCategory = this.categoryRepo.save(category);

        return this.modelMapper.map(savedCategory, CategoryDto.class);
    }

    @Override
    public CategoryDto getCategoryById(Integer categoryId) {
        Category category = this.categoryRepo.findById(categoryId).orElseThrow(() -> new ResourceNotFoundException("Category", "categoryId", categoryId));
        return this.modelMapper.map(category, CategoryDto.class);
    }

    @Override
    public List<CategoryDto> getCategories() {
        List<Category> categoryList = this.categoryRepo.findAll();
        List<CategoryDto> categoryDtoList = categoryList.stream().map(item -> this.modelMapper.map(item, CategoryDto.class)).collect(Collectors.toList());
        return categoryDtoList;
    }

    @Override
    public CategoryDto updateCategory(Integer categoryId, CategoryDto categoryDto) {
        Category category = this.categoryRepo.findById(categoryId).orElseThrow(() -> new ResourceNotFoundException("Category", "categoryId", categoryId));
        category.setCategoryTitle(categoryDto.getCategoryTitle());
        category.setCategoryDescription(categoryDto.getCategoryDescription());

        Category updatedCategory = this.categoryRepo.save(category);

        return this.modelMapper.map(updatedCategory, CategoryDto.class);
    }

    @Override
    public void deleteCategory(Integer categoryId) {
        Category category = this.categoryRepo.findById(categoryId).orElseThrow(() -> new ResourceNotFoundException("Category", "categoryId", categoryId));

        this.categoryRepo.delete(category);

    }
}
