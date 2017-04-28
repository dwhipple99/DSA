package dwhipple;

// This is a test program for testing my DSA (Digital Signature) class library.
//
// Programmer - David Whipple
//
// Libariers uses include the Apache commons CLI framework for creating my CLI options.
//

import java.io.*;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import org.apache.commons.cli.*;
import java.security.spec.*;
import java.security.KeyFactory;
import java.security.interfaces.*;
import java.security.PublicKey;

/**
 * Created by dawhippl on 4/22/17.
 */
public class Tester {

    // A method to read in file contents
    private static String readFile(String file) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader (file));
        String         line = null;
        StringBuilder  stringBuilder = new StringBuilder();
        String         ls = System.getProperty("line.separator");

        try {
            while((line = reader.readLine()) != null) {
                stringBuilder.append(line);
                stringBuilder.append(ls);
            }

            return stringBuilder.toString();
        } finally {
            reader.close();
        }
    }

    // A method that implements the CLI argument parsing, based on the Apache commons library.
    public static class Cli
    {
        private static Options options = new Options();

        /**
         * Apply Apache Commons CLI Parser to command-line arguments.
         *
         * @param commandLineArguments Command-line arguments to be processed with
         *    parser.
         */
        public static void useParser(Dsa d, final String[] commandLineArguments)
        {
            final CommandLineParser cmdLineParser = new DefaultParser();

            final Options Options = constructOptions();
            CommandLine commandLine;
            try
            {
                commandLine = cmdLineParser.parse(Options, commandLineArguments);
                if ( commandLine.hasOption("sign") )
                {
                    d.signatureFile = commandLine.getOptionValue("sign");
                    d.sign = true;
                }
                if ( commandLine.hasOption("sha1") )
                {
                    d.sha1 = true;
                    d.sha256 = false;
                    if (commandLine.hasOption("sha256")){
                        System.out.println("<WARNING>: You can only select one hash algorithm, SHA256 will be used.");
                    }
                }
                if ( commandLine.hasOption("sha256") )
                {
                    d.sha1 = false;
                    d.sha256 = true;
                }
                if ( commandLine.hasOption("genkeysonly") )
                {
                    d.genKeysOnly = true;
                }
                if ( commandLine.hasOption("supportedalgorithms") )
                {
                    d.supportedAlgorithms = true;
                }
                if ( commandLine.hasOption("verify") )
                {
                    d.verify = true;
                }
                if ( commandLine.hasOption("privatekey") )
                {
                    d.privateKeyFile = commandLine.getOptionValue("privatekey");
                }
                if ( commandLine.hasOption("publickey") )
                {
                    d.publicKeyFile = commandLine.getOptionValue("publickey");
                }
                if ( commandLine.hasOption("message") )
                {
                    d.message = true;
                    d.messageFile = commandLine.getOptionValue("message");
                }
                if ( commandLine.hasOption("verbose") )
                {
                    d.verbose = true;
                }
                boolean providedL = false;
                int tempL=1024;
                int tempN=160;
                if ( commandLine.hasOption("L") )
                {
                    tempL = Integer.parseInt(commandLine.getOptionValue("l"));
                    providedL = true;
                }
                if ( commandLine.hasOption("N") )
                {
                    System.out.println("<-INFO-->: Attempting to set L to "+tempL);
                    tempN = Integer.parseInt(commandLine.getOptionValue("n"));
                    System.out.println("<-INFO-->: Attempting to set N to "+tempN);
                    d.SelectHashFunction(tempL, tempN);
                }
                else {
                    if (providedL){
                        System.out.println("<WARNING>: If you provide a value for L, you must provide a value for N also (nothing changed), L="+d.L+", N="+d.N);
                    }
                }

            }
            catch (ParseException parseException)  // checked exception
            {
                System.err.println(
                        "<-ERROR->: Encountered exception while parsing using Parser:\n"
                                + parseException.getMessage() );
            }
        }

        /**
         * Construct and provide Options.
         *
         * @return Options expected from command-line of form.
         */
        public static Options constructOptions()
        {
            final Options Options = new Options();
            Options.addOption("sign", true, "Signature file to create or validate.")
                    .addOption("genkeysonly", false, "Use this option to generate public/private keys only, then exit.")
                    .addOption("supportedalgorithms", false, "This will print the supported security algorithms in the JVM under use, then exit.")
                    .addOption("sha1", false, "This will use the SHA-1 with DSA algorithm for the message digest hash, and signature.")
                    .addOption("sha256", false, "This will use the SHA-256 with DSA algorithm for the message digest hash, and signature.")
                    .addOption("message", true, "Message file to sign/verify.")
                    .addOption("verify", false, "Verify message file with signature file given.")
                    .addOption("privatekey", true, "File to write private key too.")
                    .addOption("publickey", true, "File to write public key too.")
                    .addOption("verbose", false, "Turn verbose mode on.")
                    .addOption("L", true, "Set the value of L for signing (valid values are 1024, 2048, 3072).")
                    .addOption("N", true, "Set the value of N for signing (valid values are 160, 224, 256).");
            return Options;
        }

        /**
         * Display example application header.
         *
         * @out OutputStream to which header should be written.
         */
        public static void displayHeader(final OutputStream out)
        {
            final String header =
                    "[DSA SIGN/VERIFY SYSTEM]\n";
            try
            {
                out.write(header.getBytes());
            }
            catch (IOException ioEx)
            {
                System.out.println(header);
            }
        }

        /**
         * Write the provided number of blank lines to the provided OutputStream.
         *
         * @param numberBlankLines Number of blank lines to write.
         * @param out OutputStream to which to write the blank lines.
         */
        public static void displayBlankLines(
                final int numberBlankLines,
                final OutputStream out)
        {
            try
            {
                for (int i=0; i<numberBlankLines; ++i)
                {
                    out.write("\n".getBytes());
                }
            }
            catch (IOException ioEx)
            {
                for (int i=0; i<numberBlankLines; ++i)
                {
                    System.out.println();
                }
            }
        }

        /**
         * Print usage information to provided OutputStream.
         *
         * @param applicationName Name of application to list in usage.
         * @param options Command-line options to be part of usage.
         * @param out OutputStream to which to write the usage information.
         */
        public static void printUsage(
                final String applicationName,
                final Options options,
                final OutputStream out)
        {
            final PrintWriter writer = new PrintWriter(out);
            final HelpFormatter usageFormatter = new HelpFormatter();
            usageFormatter.printUsage(writer, 80, applicationName, options);
            writer.flush();
        }

        /**
         * Write "help" to the provided OutputStream.
         */
        public static void printHelp(
                final Options options,
                final int printedRowWidth,
                final String header,
                final String footer,
                final int spacesBeforeOption,
                final int spacesBeforeOptionDescription,
                final boolean displayUsage,
                final OutputStream out)
        {
            //final String commandLineSyntax = "Tester -sign signaturefile -message messagefile [-verify] [-verbose]";
            final String commandLineSyntax = "Tester";
            final PrintWriter writer = new PrintWriter(out);
            final HelpFormatter helpFormatter = new HelpFormatter();
            helpFormatter.printHelp(
                    writer,
                    printedRowWidth,
                    commandLineSyntax,
                    header,
                    options,
                    spacesBeforeOption,
                    spacesBeforeOptionDescription,
                    footer,
                    displayUsage);
            writer.flush();
        }
    }

    public static boolean fileExists(String fileName){
        File varTmpDir = new File(fileName);
        boolean exists = varTmpDir.exists();
        return exists;
    }

    public static void main(final String[] commandLineArguments) throws Exception {

        // printed in CLI.
        final String applicationName = "DSA SIGN/VERIFY UTILITY";

        // Create new DSA object used for everything
        Dsa d = new Dsa();

        // Set up and run the CLI
        Cli myCli = new Cli();

        myCli.displayBlankLines(1, System.out);
        myCli.displayHeader(System.out);
        myCli.displayBlankLines(2, System.out);
        if (commandLineArguments.length < 1)
        {
            System.out.println("-- USAGE --");
            myCli.displayBlankLines(1, System.out);
            myCli.printUsage(applicationName, myCli.constructOptions(), System.out);

            myCli.displayBlankLines(4, System.out);

            System.out.println("-- HELP --");
            myCli.displayBlankLines(1, System.out);
            myCli.printHelp(
                    myCli.constructOptions(), 80, "HELP", "End of Help",
                    5, 3, true, System.out);
        }
        //myCli.displayProvidedCommandLineArguments(commandLineArguments, System.out);

        myCli.useParser(d, commandLineArguments);
        // End of CLI

        if (d.supportedAlgorithms){
            if (d.verbose) System.out.println("<VERBOSE>: Printing security algorithms supported by this version of Java.");
            d.supportedAlgorithmsInThisJava();
            System.out.println("<-EXIT-->: Exiting...");
            System.exit(0);
        }
        if (d.genKeysOnly){
            if (d.verbose) System.out.println("<VERBOSE>: Generating public and private keys only.");
            d.generate_keys(d);
            System.out.println("<-EXIT-->: Exiting...");
            System.exit(0);
        }

        if (!fileExists(d.messageFile)) {
            if (d.verbose) System.out.println("<-ERROR->: Message file does not exist.");
            System.out.println("<-EXIT-->: Exiting...");
            System.exit(1);
        }



        if (!(d.sign) && !(d.verify)){
            System.out.println("<-ERROR->: Must generate keys only, sign or verify, exiting.");
            System.out.println("<-EXIT-->: Exiting...");
            System.exit(1);
        }
        if ((d.sign) && !(d.message)){
            System.out.println("<-ERROR->: Must provide message file and signature file.");
            System.out.println("<-EXIT-->: Exiting...");
            System.exit(1);

        }
        if ((d.sign) && !(d.verify)){
            if (fileExists(d.signatureFile)){
                System.out.println("<-ERROR->: Signature file already exists, either delete or add -verify to verify using existing signature file");
                System.out.println("<-EXIT-->: Exiting...");
                System.exit(1);
            }
            System.out.println("<-INFO-->: Creating signature file only, use both -sign and -verify if you want to validate.");
        }

        // Execute commands from CLI
        System.out.println("<-INFO-->: Welcome to the DSA Algorithm package.");

        if (d.verbose) System.out.println("<VERBOSE>: Verbose="+d.verbose);

        // Load the message

        if (!fileExists(d.messageFile)){
            System.out.println("<-ERROR->: Message file does not exist.");
            System.out.println("<-EXIT-->: Exiting...");
            System.exit(1);
        }
        if (d.verbose) System.out.println("<VERBOSE>: Reading message file - "+ d.messageFile);
        String message = readFile(d.messageFile);
        byte[] dataBytes = message.getBytes();

        if (d.sign) {
            // See if signature file already exists.
            if (fileExists(d.signatureFile)) {
                if (d.verbose) System.out.println("<-INFO-->: Signature file already exists, so using existing signature to verify message.");
                d.useExistingSignature = true;
            }
            else {
                if (d.verbose) System.out.println("<-INFO-->: Signature file does not exist, creating it.");

                // Sign the message
                if (d.verbose) System.out.println("<-INFO-->: Overwriting private and public key files since signature file does not exist.");
                d.generate_keys(d);
                if (d.verbose) {
                    //System.out.println("Private key is "+d.privateKey);
                    System.out.println("<VERBOSE>: Public key is " + d.publicKey);
                }
                byte[] signature = d.sign(d, message, dataBytes, d.privateKey, d.publicKey);

            }

        }
        if (d.verify) {
            // Load the signature
            if (d.verbose) System.out.println("<VERBOSE>: Reading signature file - "+ d.signatureFile);
            FileInputStream sigfis = new FileInputStream(d.signatureFile);
            byte[] sigToVerify = new byte[sigfis.available()];
            sigfis.read(sigToVerify);
            sigfis.close();

            // Load the public key
            if (d.verbose) System.out.println("<-INFO-->: Loading public key from "+d.publicKeyFile);
            FileInputStream keyfis = new FileInputStream(d.publicKeyFile);
            byte[] encKey = new byte[keyfis.available()];
            keyfis.read(encKey);
            keyfis.close();
            // Convert byte array back to DSA Public Key.
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
            KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);
            d.publicKey = (DSAPublicKey)pubKey;

            // Validate the signature
            //d.verify(d, message, dataBytes, d.privateKey, d.publicKey, sigToVerify);
            d.verify(d, message, dataBytes, d.privateKey, d.publicKey, sigToVerify);

        }

        System.out.println("<-EXIT-->: Exiting...");

    }
}
