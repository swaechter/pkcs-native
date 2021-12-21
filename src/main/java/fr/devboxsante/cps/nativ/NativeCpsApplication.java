package fr.devboxsante.cps.nativ;

import iaik.pkcs.pkcs11.Module;

import java.lang.reflect.Method;

public class NativeCpsApplication {

//    public static final String MODULE = "C:\\Windows\\System32\\cps3_pkcs11_w64.dll";

    public static void main(String[] args) {
        Method m;
        try {
            // Load the library
            m = Class.forName("iaik.pkcs.pkcs11.wrapper.PKCS11Implementation").getDeclaredMethod("initializeLibrary");
            System.loadLibrary("pkcs11wrapper");
            m.setAccessible(true);
            m.invoke(null);
            System.out.println("Library loaded!");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
