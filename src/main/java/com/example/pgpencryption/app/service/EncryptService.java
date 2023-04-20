package com.example.pgpencryption.app.service;

import com.example.pgpencryption.app.utils.CommonUtils;
import lombok.Builder;
import lombok.NoArgsConstructor;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Objects;

@Builder
public class EncryptService {

    @Builder.Default
    private int compressionAlgorithm = CompressionAlgorithmTags.ZIP;
    @Builder.Default
    private int symmetricKeyAlgorithm = SymmetricKeyAlgorithmTags.AES_128;
    @Builder.Default
    private boolean armor = false;
    @Builder.Default
    private boolean withIntegrityCheck = false;
    @Builder.Default
    private int bufferSize = 1 << 16;

    static {
        if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void encrypt(OutputStream result, InputStream originalFile, long length, InputStream publicKey) throws PGPException, IOException {
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(compressionAlgorithm);
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        );
        encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(CommonUtils.getPublicKey(publicKey)));

        if (armor) {
            result = new ArmoredOutputStream(result);
        }
        OutputStream cipherOutputStream = encryptedDataGenerator.open(result, new byte[bufferSize]);
        CommonUtils.copyAsLiteralData(compressedDataGenerator.open(cipherOutputStream), originalFile, length, bufferSize);
        compressedDataGenerator.close();
        cipherOutputStream.close();
        result.close();
    }

    public byte[] encrypt(byte[] originalFile, InputStream pubicKeyIn) throws PGPException, IOException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(originalFile);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        encrypt(outputStream, inputStream, originalFile.length, pubicKeyIn);
        return outputStream.toByteArray();
    }

    public InputStream encrypt(InputStream originalFile, long length, InputStream publicKeyIn)
            throws IOException, PGPException {
        File tempFile = File.createTempFile("fwd-", "-encrypted");
        encrypt(Files.newOutputStream(tempFile.toPath()), originalFile, length, publicKeyIn);
        return Files.newInputStream(tempFile.toPath());
    }

//    public byte[] encrypt(byte[] clearData, String publicKeyStr) throws PGPException, IOException {
//        return encrypt(clearData, IOUtils.toInputStream(publicKeyStr, Charset.defaultCharset()));
//    }
//
//    public InputStream encrypt(InputStream clearIn, long length, String publicKeyStr) throws IOException, PGPException {
//        return encrypt(clearIn, length, IOUtils.toInputStream(publicKeyStr, Charset.defaultCharset()));
//    }
}
