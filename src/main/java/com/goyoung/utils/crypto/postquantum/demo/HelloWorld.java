package com.goyoung.utils.crypto.postquantum.demo;

import org.apache.maven.plugin.MojoExecutionException;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256KeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256Signer;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;

/**
 * Created by gyoung on 10/8/16.
 */
public class HelloWorld {
    public static void main(String[] args) throws MojoExecutionException {

        SPHINCS256KeyPairGenerator generator = new SPHINCS256KeyPairGenerator();
        generator.init(new SPHINCS256KeyGenerationParameters(new SecureRandom(), new SHA3Digest(256)));
        AsymmetricCipherKeyPair kp = generator.generateKeyPair();
        SPHINCSPrivateKeyParameters priv = (SPHINCSPrivateKeyParameters) kp.getPrivate();
        SPHINCSPublicKeyParameters pub = (SPHINCSPublicKeyParameters) kp.getPublic();
        MessageSigner sphincsSigner = new SPHINCS256Signer(new SHA3Digest(256), new SHA3Digest(512));
        sphincsSigner.init(true, priv);
        byte[] sig = sphincsSigner.generateSignature("This is a test".getBytes());
        String out = new String(sig);

        sphincsSigner.init(false, pub);
        //isTrue("sha3 r sig verify failed", sphincsSigner.verifySignature(msg, sig));
        //isTrue("sha3 r wrong verify failed", !sphincsSigner.verifySignature(msg, expBlakeSig));


        System.out.println(out);
    }
}
