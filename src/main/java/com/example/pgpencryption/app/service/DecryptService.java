package com.example.pgpencryption.app.service;

import com.example.pgpencryption.app.utils.CommonUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.io.*;
import java.nio.charset.Charset;
import java.security.Security;
import java.util.Iterator;
import java.util.Objects;

public class DecryptService {

    static {
        if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final char[] passCode;

    private final PGPSecretKeyRingCollection secretKeyRings;

    public DecryptService(InputStream privateKey, String passCode) throws IOException, PGPException {
        this.passCode = passCode.toCharArray();
        this.secretKeyRings = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKey), new JcaKeyFingerprintCalculator());
    }

    public DecryptService(String privateKey, String passCode) throws PGPException, IOException {
        this(IOUtils.toInputStream(privateKey, Charset.defaultCharset()), passCode);
    }

    private PGPPrivateKey findSecretKey(long keyID) throws PGPException {
        PGPSecretKey pgpSecretKey = secretKeyRings.getSecretKey(keyID);
        return pgpSecretKey == null ? null : pgpSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(passCode));
    }

    public void decrypt(InputStream encryptedFile, OutputStream resultStream) throws IOException, PGPException {
        encryptedFile = PGPUtil.getDecoderStream(encryptedFile);
        JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(encryptedFile);

        Object obj = pgpObjectFactory.nextObject();

        PGPEncryptedDataList encryptedDataList = (obj instanceof PGPEncryptedDataList)
                ? (PGPEncryptedDataList) obj
                : (PGPEncryptedDataList) pgpObjectFactory.nextObject();

        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData publicKeyEncryptedData = null;

        Iterator<PGPEncryptedData> encryptedDataIterator = encryptedDataList.getEncryptedDataObjects();

        while (privateKey == null && encryptedDataIterator.hasNext()) {
            publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataIterator.next();
            privateKey = findSecretKey(publicKeyEncryptedData.getKeyID());
        }

        if (Objects.isNull(publicKeyEncryptedData)) {
            throw new PGPException("Could not generate PGPPublicKeyEncryptedData object");
        }

        if (privateKey == null) {
            throw new PGPException("Could Not Extract private key");
        }
        CommonUtils.decrypt(resultStream, privateKey, publicKeyEncryptedData);
    }

    public byte[] decrypt(byte[] encryptedBytes) throws PGPException, IOException {
        ByteArrayInputStream encryptedFile = new ByteArrayInputStream(encryptedBytes);
        ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
        decrypt(encryptedFile, resultStream);
        return resultStream.toByteArray();
    }
}
