package com.example.pgpencryption.app.utils;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.*;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Optional;

public class CommonUtils {

    public static void decrypt(OutputStream resultStream, PGPPrivateKey privateKey, PGPPublicKeyEncryptedData publicKeyEncryptedData) throws PGPException, IOException {
        PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
        InputStream decryptCompressed = publicKeyEncryptedData.getDataStream(decryptorFactory);
        JcaPGPObjectFactory decComprObjFact = new JcaPGPObjectFactory(decryptCompressed);
        PGPCompressedData pgpCompressedData = (PGPCompressedData) decComprObjFact.nextObject();

        InputStream compressedDataStream = new BufferedInputStream(pgpCompressedData.getDataStream());
        JcaPGPObjectFactory pgpCompObjFac = new JcaPGPObjectFactory(compressedDataStream);

        Object message = pgpCompObjFac.nextObject();

        if (message instanceof PGPLiteralData) {
            PGPLiteralData pgpLiteralData = (PGPLiteralData) message;
            InputStream decDataStream = pgpLiteralData.getInputStream();
            IOUtils.copy(decDataStream, resultStream);
            resultStream.close();
        } else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("Encrypted message contains a signed message not literal data");
        } else {
            throw new PGPException("Message is not a simple encrypted file - Type Unknown");
        }
        // Performing Integrity check
        if (publicKeyEncryptedData.isIntegrityProtected()) {
            if (!publicKeyEncryptedData.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        }
    }

    public static void copyAsLiteralData(OutputStream outputStream, InputStream inputStream, long length, int bufferSize) throws IOException {
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream pgpOutStream = literalDataGenerator.open(outputStream, PGPLiteralDataGenerator.BINARY, PGPLiteralData.CONSOLE, Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)), new byte[bufferSize]);
        byte[] buffer = new byte[bufferSize];
        try (inputStream) {
            int len;
            long totalBytesWritten = 0L;
            while (totalBytesWritten <= length && (len = inputStream.read(buffer)) > 0) {
                pgpOutStream.write(buffer, 0, len);
                totalBytesWritten += len;
            }
            pgpOutStream.close();
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    public static PGPPublicKey getPublicKey(InputStream keyInputStream) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPublicKeyRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> keyRingIterator = pgpPublicKeyRings.getKeyRings();
        while (keyRingIterator.hasNext()) {
            PGPPublicKeyRing pgpPublicKeyRing = keyRingIterator.next();
            Optional<PGPPublicKey> pgpPublicKey = extractPGPKeyFromRing(pgpPublicKeyRing);
            if (pgpPublicKey.isPresent()) {
                return pgpPublicKey.get();
            }
        }
        throw new PGPException("Invalid public key");
    }

    private static Optional<PGPPublicKey> extractPGPKeyFromRing(PGPPublicKeyRing pgpPublicKeyRing) {
        for (PGPPublicKey publicKey : pgpPublicKeyRing) {
            if (publicKey.isEncryptionKey()) {
                return Optional.of(publicKey);
            }
        }
        return Optional.empty();
    }

    public static void createDirectory(String path) throws IOException {
        if (Files.notExists(Path.of(path))) {
            new File(path).mkdirs();
        }
    }

}
