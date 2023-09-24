package fr.devboxsante.cps.nativ;

import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;

import java.io.File;

public class Launcher {

    public static void main(String[] args) throws Throwable {
        // Load the PKCS11 middleware
        System.out.println("Going to load the PKCS11 library");
        System.load(new File("pkcs11wrapper.dll").getAbsolutePath());
        System.out.println("Done");

        // Initialize the middleware
        System.out.println("Going to initialize the PKCS11 middleware instance");
        Module module = Module.getInstance("cryptoki");
        module.initialize(new DefaultInitializeArgs());
        System.out.println("Done");

        // Finalize the middleware
        System.out.println("Going to finalize the PKCS11 middlware");
        module.finalize();
        System.out.println("Done");
    }
}
