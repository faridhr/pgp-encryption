package com.example.pgpencryption.app.controllers;

import com.example.pgpencryption.app.service.DecryptService;
import com.example.pgpencryption.app.service.EncryptService;
import com.example.pgpencryption.app.utils.CommonUtils;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.openpgp.PGPException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/encrypt-decrypt")
public class EncryptDecryptController {

    private EncryptService encryptService;

    private DecryptService decryptService;

    @Value("classpath:keystore/0x022F7AC5-sec.asc")
    private Resource privateKey;

    @Value("classpath:keystore/0x022F7AC5-pub.asc")
    private Resource publicKey;

    @Value("${app.storage.directory.destination}")
    private String destination;

    @Value("${app.security.passphrase}")
    private String passphrase;

    @GetMapping("/encrypt")
    public ResponseEntity<?> encrypt(@RequestParam("files") MultipartFile[] files) {
        encryptService = EncryptService.builder().armor(false).withIntegrityCheck(false).build();
        Map<String, List<String>> response = new HashMap<>();
        List<File> resultFiles = new ArrayList<>();
        for (MultipartFile file : files) {
            try (InputStream encrypted = encryptService.encrypt(file.getInputStream(), file.getSize(), publicKey.getInputStream())) {
                CommonUtils.createDirectory(destination.concat("/encrypted"));
                String filename = Optional.ofNullable(file.getOriginalFilename()).orElse(UUID.randomUUID().toString());
                File tempFile = new File(destination.concat("/encrypted/").concat(filename).concat("-encrypt"));
                FileUtils.copyInputStreamToFile(encrypted, tempFile);
                resultFiles.add(tempFile);
            } catch (IOException | PGPException e) {
                e.printStackTrace();
            }
        }
        response.put("result", resultFiles.stream().map(File::getAbsolutePath).collect(Collectors.toList()));
        return ResponseEntity.ok(response);
    }

    @GetMapping("/decrypt")
    public ResponseEntity<?> decrypt(@RequestParam("files") MultipartFile[] files) throws IOException, PGPException {
        decryptService = new DecryptService(privateKey.getInputStream(), passphrase);
        Map<String, List<String>> response = new HashMap<>();
        List<File> resultFiles = new ArrayList<>();
        for (MultipartFile file : files) {
            try {
                CommonUtils.createDirectory(destination.concat("/decrypted"));
                String originalName = Optional.ofNullable(file.getOriginalFilename()).orElse(UUID.randomUUID().toString());
                String filename = originalName.substring(0, originalName.lastIndexOf("-"));
                File tempFile = new File(destination.concat("/decrypted/").concat(filename));
                decryptService.decrypt(file.getInputStream(), Files.newOutputStream(tempFile.toPath()));
                resultFiles.add(tempFile);
            } catch (IOException | PGPException e) {
                e.printStackTrace();
            }
        }
        response.put("result", resultFiles.stream().map(File::getAbsolutePath).collect(Collectors.toList()));
        return ResponseEntity.ok(response);
    }
}
