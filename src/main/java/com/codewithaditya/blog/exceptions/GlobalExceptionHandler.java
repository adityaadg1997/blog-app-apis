package com.codewithaditya.blog.exceptions;

import com.codewithaditya.blog.payloads.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiResponse> resourceNotFoundExceptionHandler(ResourceNotFoundException exception) {
        String message = exception.getMessage();
        ApiResponse apiResponse = new ApiResponse(message, false);

        return new ResponseEntity<>(apiResponse, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String,String>> methodArgumentNotValidExceptionHandler(MethodArgumentNotValidException exception){
        Map<String, String> response = new HashMap<>();

        exception.getBindingResult().getFieldErrors().forEach((fieldError -> {
                    String fieldName = fieldError.getField();
                    String message = fieldError.getDefaultMessage();
                    response.put(fieldName, message);
                }));

        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse> httpRequestMethodNotSupportedExceptionHandler(HttpRequestMethodNotSupportedException exception){
        String message = exception.getMessage();

        return new ResponseEntity<>(new ApiResponse(message + " Invalid Request Url", false), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(FileNotFoundException.class)
    public ResponseEntity<ApiResponse> fileNotFoundException(FileNotFoundException exception){

        String message = exception.getMessage();

        return new ResponseEntity<>(new ApiResponse(message, false), HttpStatus.NOT_FOUND);

    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ApiResponse> apiException(ApiException exception){

        String message = exception.getMessage();

        return new ResponseEntity<>(new ApiResponse(message, false), HttpStatus.BAD_REQUEST);

    }
}
