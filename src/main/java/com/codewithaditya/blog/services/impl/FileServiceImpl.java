package com.codewithaditya.blog.services.impl;

import com.codewithaditya.blog.services.FileService;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.UUID;

@Service
public class FileServiceImpl implements FileService {
    @Override
    public String uploadFile(String path, MultipartFile file) throws IOException {

        //file name
        String fileName = file.getOriginalFilename();

        //generate random file name
        String randomID = UUID.randomUUID().toString();
        String randomFileName = randomID.concat(fileName.substring(fileName.lastIndexOf("."))); //it will extract string from . like .png .jpg

        //full path
        String fullPath = path + File.separator + randomFileName;

        //create folder
        File folder = new File(path);
        if(!folder.exists()){
            folder.mkdir();
        }

        //upload code
        Files.copy(file.getInputStream(), Paths.get(fullPath));


        return randomFileName;
    }

    //serve file
    @Override
    public InputStream getResource(String path, String fileName) throws FileNotFoundException {

        String fullPath = path+File.separator+fileName;

        InputStream inputStream = new FileInputStream(fullPath);

        return inputStream;
    }
}
