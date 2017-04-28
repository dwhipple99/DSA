package dwhipple;

/**
 * Created by dawhippl on 4/12/17.
 *
 * Implementing the DSA (Digitial Signature Algorithm for Signing Messages).
 *
 * FIP's Standard can be found here:
 * http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
 *
 * Also implementing RFC6979
 * https://tools.ietf.org/html/rfc6979
 *
 */

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.io.*;
import java.util.Arrays;
import java.util.Random;

public class Dsa {

    // From http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
    //
    // p - a prime modulus, where 2L–1 < p < 2L, and L is the bit length of p. Values for L are
    //     provided in Section 4.2.
    // q - a prime divisor of (p – 1), where 2N–1 < q < 2 N, and N is the bit length of q. Values for N
    //     are provided in Section 4.2.
    // g - a generator of a subgroup of order q in the multiplicative group of GF(p), such that 1 < g
    //     < p.
    // x - the private key that must remain secret; x is a randomly or pseudorandomly generated
    //     integer, such that 0 < x < q, i.e., x is in the range [1, q–1].
    // y - the public key, where y = gx mod p.
    // k - a secret number that is unique to each message; k is a randomly or pseudorandomly
    //     generated integer, such that 0 < k < q, i.e., k is in the range [1, q–1].
    //
    // This Standard specifies the following choices for the pair L and N (the bit lengths of p and q,
    //                                                                     respectively):
    // L = 1024, N = 160
    // L = 2048, N = 224
    // L = 2048, N = 256
    // L = 3072, N = 256

    BigInteger p;   // a prime modulus
    BigInteger q;   // a prime divisor
    BigInteger g;   // a generator
    BigInteger x;   // private key
    BigInteger y;   // public key
    BigInteger r;   // Value of r
    BigInteger s;   // Value of s
    BigInteger k;   // Value of k
    Random domain_parameter_seed;
    BigInteger counter;
    KeyPairGenerator keyGen;
    KeyPair keypair;
    DSAPrivateKey privateKey;
    DSAPublicKey publicKey;
    int L = 1024;
    int N = 160;
    boolean verbose = false;
    boolean sign = false;
    boolean verify = false;
    boolean message = false;
    boolean useExistingSignature = false;
    boolean genKeysOnly = false;
    boolean supportedAlgorithms = false;
    boolean sha1 = true;
    boolean sha256 = false;
    String messageFile="message";
    String signatureFile="signature";
    String privateKeyFile="privatekey";
    String publicKeyFile="publickey";
    String hashAlgorithm="SHA-1";
    String signHashAlgorithm="SHA1withDSA";


    //Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);

    // This is the class that implements all of the algorithm including
    // creating public and private keys, signing, and/or verifying a valid
    // signature.
    public Dsa() {

        //logger.setLevel(Level.WARNING);

        if (!SelectHashFunction(1024, 160)) {
            System.out.println("<-ERROR->: Invalid values of L & N");
        }
        ;

        // Generate a new random seed for computing p,q
        if (this.verbose) System.out.println("<VERBOSE>: Creating DSA Object.");
        //logger.log(Level.INFO, "Log level is " + logger.getLevel());
        //logger.log(Level.INFO, "Creating DSA object.");
        this.domain_parameter_seed = new Random();
    }

    // This method is used to list what Security Algorithms this Java implementation supports.
    // This was provided online.
    public static void supportedAlgorithmsInThisJava() {
        System.out.println("<-INFO-->: Algorithms Supported in this JCE.");
        System.out.println("<-INFO-->: =================================");
        // heading
        System.out.println("<-INFO-->: Provider: type.algorithm -> className" + "\n  aliases:" + "\n  attributes:\n");
        // discover providers
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            System.out.println("<><><>" + provider + "<><><>\n");
            // discover services of each provider
            for (Provider.Service service : provider.getServices()) {
                System.out.println(service);
            }
            System.out.println();
        }
    }

    // This method is used to modify the values of L & N for DSA key generation.
    public boolean SelectHashFunction(int NewL, int NewN) {

        if (NewL == 1024) {
            if (NewN == 160) {
                L = NewL;
                N = NewN;
                System.out.println("<PARAMETER CHANGE>: Setting hash parameters L=" + L + ",N=" + N);
                return true;
            }
        }
        if (NewL == 2048) {
            if ((NewN == 224) || (NewN == 256)) {
                L = NewL;
                N = NewN;
                System.out.println("<PARAMETER CHANGE>: Setting hash parameters L=" + L + ",N=" + N);
                return true;
            }
        }
        if (NewL == 3072) {
            if (NewN == 256) {
                //L = NewL;
                //N = NewN;
                System.out.println("<WARNING>: Unsupported combination for DSA L=" + NewL + ",N=" + NewN);
                return true;
            }
        }
        System.out.println("<WARNING>: Invalid values for L or N, values not changed, L=" + L + ", N=" + N);
        return false;
    }


    // This method is used for signing a message file.
    //
    public byte[] sign(Dsa DSAObject, String message, byte[] dataBytes, DSAPrivateKey privateKey, DSAPublicKey publicKey) {

        BigInteger h=BigInteger.ZERO;
        BigInteger BigZero=BigInteger.ZERO;
        byte[] realSignature = new byte[1024];

        if (DSAObject.sha256) {
            hashAlgorithm = "SHA-256";
            signHashAlgorithm = "SHA256withDSA";
        }

        if (DSAObject.verbose) System.out.println("<VERBOSE>: Creating digital signature using DSA standard.");
        //logger.log(Level.INFO, "Creating digitial signature using DSA standard.");
        if (DSAObject.verbose) System.out.println("<VERBOSE>: Signing the message \"" + message + "\"");
        //System.out.println("Private Key is "+privateKey);
        // Create digest
        try {
            if (DSAObject.verbose) System.out.println("<VERBOSE>: Using algorithm "+DSAObject.hashAlgorithm);
            MessageDigest md = MessageDigest.getInstance(DSAObject.hashAlgorithm);
            byte[] mdbytes = md.digest();
            h = new BigInteger(1, mdbytes);
            if (DSAObject.verbose) System.out.println("<VERBOSE>: Using signature algorithm "+DSAObject.signHashAlgorithm);
            Signature dsa = Signature.getInstance(DSAObject.signHashAlgorithm, "SUN");
            dsa.initSign(privateKey);
            dsa.update(dataBytes);
            realSignature = dsa.sign();
            DSAObject.r = DSAObject.getR(realSignature);
            DSAObject.s = DSAObject.getS(realSignature);
            DSAObject.k = DSAObject.getK(realSignature, h, DSAObject.privateKey, true);
            if (DSAObject.verbose) System.out.println("<VERBOSE>: The value of r="+DSAObject.r);
            if ((r == BigZero) || (s == BigZero)){
                System.out.println("<ERROR>: Invalid values of r or s, they were 0");
                System.exit(1);
            }
            if (DSAObject.verbose) System.out.println("<VERBOSE>The value of s="+DSAObject.s);
            if (DSAObject.verbose) System.out.println("<VERBOSE>The value of k="+DSAObject.k);
            if (DSAObject.verbose) System.out.println("<VERBOSE>: Signature is " + Arrays.toString(realSignature));

            /* save the signature in a file */
            try {
                if (verbose) {
                    System.out.println("<-INFO-->: Writing signature to " + DSAObject.signatureFile);
                }
                FileOutputStream sigfos = new FileOutputStream(DSAObject.signatureFile);
                sigfos.write(realSignature);
                sigfos.close();
                return realSignature;

            } catch (FileNotFoundException x) {
                System.out.println("<-ERROR->: File can't be opened.");
                System.exit(1);
            } catch (IOException x) {
                System.out.println("<-ERROR->: File can't be opened.");
                System.exit(1);
            }

        } catch (NoSuchAlgorithmException x) {
            System.out.println("<-ERROR->: Hash algorithm not supported - " + x);
            System.exit(1);
        } catch (NoSuchProviderException y) {
            System.out.println("<-ERROR->: Provider not supported - " + y);
            System.exit(1);
        } catch (InvalidKeyException z) {
            System.out.println("<-ERROR->: Invalid Key Exception - " + z);
            System.exit(1);
        } catch (SignatureException t) {
            System.out.println("<-ERROR->: Signature Exception - " + t);
            System.exit(1);
        } catch (java.lang.Exception a){
            System.out.println("<-ERROR->: java.lang.Exception Exception - " + a);
            System.exit(1);
        }

        return realSignature;
    }

    // This method is used to verify a message against a signature and a public key.
    public void verify(Dsa DSAObject, String message, byte[] dataBytes, DSAPrivateKey privateKey, DSAPublicKey publicKey, byte[] signature) {

        if (DSAObject.sha256) {
            hashAlgorithm = "SHA-256";
            signHashAlgorithm = "SHA256withDSA";
        }

        if (DSAObject.verbose) System.out.println("<VERBOSE>: Verifying digital signature using DSA standard.");
        //logger.log(Level.INFO, "Verifying digital signature using DSA standard.");
        if (DSAObject.verbose) System.out.println("<VERBOSE>: Verifying the signature for the message \"" + message + "\"");

        try {
            Signature sig = Signature.getInstance(DSAObject.signHashAlgorithm, "SUN");
            sig.initVerify(publicKey);
            sig.update(dataBytes);
            boolean verifies = sig.verify(signature);
            if (verifies) {
                System.out.println("<-VALID->: signature verifies is TRUE.");
            }
            else {
                System.out.println("<INVALID>: signature verifies is FALSE.");
            }

        } catch (NoSuchAlgorithmException x) {
            System.out.println("<-ERROR->: Hash algorithm not supported - " + x);
            return;
        } catch (NoSuchProviderException y) {
            System.out.println("<-ERROR->: Provider not supported - " + y);
            return;
        } catch (InvalidKeyException z) {
            System.out.println("<-ERROR->: Invalid Key Exception - " + z);
            return;
        } catch (SignatureException t) {
            System.out.println("<-ERROR->: Signature Exception - " + t);
        }
    }

    // This method is used to generate public and private keys for signing.
    public static void generate_keys(Dsa d) {

        // Generate a secure Random
        SecureRandom sRandom = new SecureRandom();

        // Generating Keys
        if (d.verbose) System.out.println("<VERBOSE>: Generating public and private keys, private key file is \""+d.privateKeyFile+"\", public key file is \""+d.publicKeyFile+"\"");
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
            keyGen.initialize(d.L, sRandom);
            KeyPair keypair = keyGen.genKeyPair();
            DSAPrivateKey privateKey = (DSAPrivateKey) keypair.getPrivate();
            DSAPublicKey publicKey = (DSAPublicKey) keypair.getPublic();
            DSAParams dsaParams = privateKey.getParams();
            d.p = dsaParams.getP();
            d.q = dsaParams.getQ();
            d.g = dsaParams.getG();
            d.x = privateKey.getX();
            d.y = publicKey.getY();
            d.privateKey = privateKey;
            d.publicKey = publicKey;
        } catch (NoSuchAlgorithmException DSA) {
            throw new IllegalStateException(DSA);
        }
        /* save the private key in a file */
        byte[] prikey = d.privateKey.getEncoded();
        try {
            FileOutputStream prikeyfos = new FileOutputStream(d.privateKeyFile);
            prikeyfos.write(prikey);
            prikeyfos.close();
        } catch (FileNotFoundException e) {
            System.out.println("<-ERROR->: File not found.");
            System.exit(1);
        } catch (IOException e) {
            System.out.println("<-ERROR->: File not found.");
            System.exit(1);
        }
        try {
            byte[] pubkey = d.publicKey.getEncoded();
            FileOutputStream pubkeyfos = new FileOutputStream(d.publicKeyFile);
            pubkeyfos.write(pubkey);
            pubkeyfos.close();
        } catch (FileNotFoundException e) {
            System.out.println("<-ERROR->: File not found.");
            System.exit(1);
        } catch (IOException e) {
            System.out.println("<-ERROR->: File not found.");
            System.exit(1);
        }
        /* save the public key in a file */
    }

    BigInteger getR(byte[] signature) throws Exception {
        int Rlen = signature[3];
        return new BigInteger(Arrays.copyOfRange(signature, 4, 4 + Rlen));
    }

    BigInteger getS(byte[] signature) throws Exception {
        int Slen = signature[3];
        int startS = 4 + Slen;
        int Slength = signature[startS + 1];
        return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + Slength));
    }

    /** Retrieve the k that was used to sign the signature. Validates the k if check == true. */
    BigInteger getK(byte[] signature, BigInteger h, DSAPrivateKey priv, boolean check)
            throws Exception {
        BigInteger x = priv.getX();
        BigInteger q = priv.getParams().getQ();
        BigInteger r = getR(signature);
        BigInteger s = getS(signature);
        BigInteger k = x.multiply(r).add(h).multiply(s.modInverse(q)).mod(q);
        if (check) {
            BigInteger p = priv.getParams().getP();
            BigInteger g = priv.getParams().getG();
            BigInteger r2 = g.modPow(k, p).mod(q);
        }
        return k;
    }


}
