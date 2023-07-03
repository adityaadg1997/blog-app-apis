package com.codewithaditya.blog.controllers;

import com.codewithaditya.blog.payloads.ApiResponse;
import com.codewithaditya.blog.payloads.CategoryDto;
import com.codewithaditya.blog.services.CategoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/category")
public class CategoryController {

    @Autowired
    private CategoryService categoryService;

    //create
    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @PostMapping("/")
    public ResponseEntity<CategoryDto> createCategory(@Valid @RequestBody CategoryDto categoryDto){
        CategoryDto category = this.categoryService.createCategory(categoryDto);

        return new ResponseEntity<>(category, HttpStatus.CREATED);
    }

    //read
    @GetMapping("/{id}")
    public ResponseEntity<CategoryDto> getCategory(@PathVariable("id") Integer id){
        CategoryDto categoryById = this.categoryService.getCategoryById(id);

        return new ResponseEntity<>(categoryById, HttpStatus.OK);
    }

    //read all
    @GetMapping("/")
    public ResponseEntity<List<CategoryDto>> getCategories(){
        List<CategoryDto> categoryDtoList = this.categoryService.getCategories();

        return new ResponseEntity<>(categoryDtoList, HttpStatus.OK);
    }

    //update
    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @PutMapping("/{categoryId}")
    public ResponseEntity<?> updateCategory(@PathVariable("categoryId") Integer categoryId,@Valid @RequestBody CategoryDto categoryDto){
        CategoryDto updatedCategory = this.categoryService.updateCategory(categoryId, categoryDto);

        return new ResponseEntity<>(updatedCategory, HttpStatus.ACCEPTED);
    }

    //delete
    @Operation(security = { @SecurityRequirement(name = "bearer-key") })
    @DeleteMapping("/{categoryId}")
    public ResponseEntity<ApiResponse> deleteCategory(@PathVariable("categoryId") Integer categoryId){
        this.categoryService.deleteCategory(categoryId);

        return new ResponseEntity<>(new ApiResponse(categoryId + " is successfully deleted !!", true), HttpStatus.OK);
    }
}
