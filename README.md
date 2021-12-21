# PKCS11-Wrapper with Native Image

## Goal

This repository tries to use the PKCS11-Wrapper from IAIK in combination with the GraalVM native image. This doesn't
work at the moment due some library loading issue.

## Setup

**Disclaimer**: If you don't trust the provided DLLs, you can get an evaluation version from https://jce.iaik.tugraz.at/products/core-crypto-toolkits/pkcs11-wrapper/

### Copy the PKCS11 JNI DLL to your Window DDL directory

Run the following command as administrator:

````powershell
cp .\libs\pkcs11wrapper.dll C:\Windows\System32\drivers\
````

**Note**: The IAIK Java source code is intregrated in the project to eliminate potential issues with older compilers.

### Include GraalVM and MSVC in the PATH variable

**Note**: Run this commands in a CMD and not in a Powershell. The MSVC setup script misbehave in the Powershell

```powershell
set GRAALVM_HOME="C:\Users\swaechter\Downloads\graalvm-ce-java17-windows-amd64-21.3.0"
set PATH=C:\Users\swaechter\Downloads\graalvm-ce-java17-21.3.0\bin;%PATH%

"C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/VC/Auxiliary/Build/vcvarsx86_amd64.bat"
```

### Build the Java application

````powershell
.\gradlew.bat clean build
````

### Run the application on the GraalVM to get runtime insights + update the files

````powershell
java.exe -agentlib:native-image-agent=config-output-dir=src/main/resources/META-INF/native-image  -jar build\libs\native.jar

.\gradlew.bat clean build
````

### Build the native image

```powershell
native-image.cmd -H:-CheckToolchain -H:+ReportExceptionStackTraces --static -jar .\build\libs\native.jar
```

### Run the native application

Run into the native application. Here we run into the problem:

````powershell
C:\Users\swaechter\Downloads\pkcs-native>.\native.exe
Exception in thread "main" java.lang.UnsatisfiedLinkError: no pkcs11wrapper in java.library.path
at com.oracle.svm.core.jdk.NativeLibrarySupport.loadLibraryRelative(NativeLibrarySupport.java:132)
at java.lang.ClassLoader.loadLibrary(ClassLoader.java:47)
at java.lang.Runtime.loadLibrary0(Runtime.java:818)
at java.lang.System.loadLibrary(System.java:1989)
at fr.devboxsante.cps.nativ.NativeCpsApplication.main(NativeCpsApplication.java:16)
````

## Implement a feature to link the library at compile time

We implement a feature to link the at compile time `LibraryFeature.java`:

````java
package fr.devboxsante.cps.nativ;

import com.oracle.svm.core.annotate.AutomaticFeature;
import com.oracle.svm.core.jdk.NativeLibrarySupport;
import com.oracle.svm.core.jdk.PlatformNativeLibrarySupport;
import com.oracle.svm.hosted.FeatureImpl;
import com.oracle.svm.hosted.c.NativeLibraries;
import org.graalvm.nativeimage.hosted.Feature;

@AutomaticFeature
public class LibraryFeature implements Feature {

    @Override
    public void beforeAnalysis(BeforeAnalysisAccess access) {
        NativeLibrarySupport.singleton().preregisterUninitializedBuiltinLibrary("pkcs11wrapper");
        PlatformNativeLibrarySupport.singleton().addBuiltinPkgNativePrefix("iaik.pkcs.pkcs11.wrapper.PKCS11Implementation"); // TODO: Not sure if this is correct
        NativeLibraries nativeLibraries = ((FeatureImpl.BeforeAnalysisAccessImpl) access).getNativeLibraries();
        nativeLibraries.addStaticJniLibrary("pkcs11wrapper");
    }
}
````

The information is taken from the issue https://github.com/oracle/graal/issues/3359 and the blog post https://www.blog.akhil.cc/static-jni

Rebuild and include the DLL into the native image run:

````powershell
.\gradlew.bat clean build

native-image.cmd --allow-incomplete-classpath --no-fallback -H:CLibraryPath=C:/Windows/System32/drivers/ --static -jar build\libs\native.jar
````

Rerun to see that we can load the library, but fail due some JNI mismatch:

````powershell
C:\Users\swaechter\Downloads\pkcs-native>native.exe
java.lang.reflect.InvocationTargetException
at java.lang.reflect.Method.invoke(Method.java:568)
at fr.devboxsante.cps.nativ.NativeCpsApplication.main(NativeCpsApplication.java:18)
Caused by: java.lang.UnsatisfiedLinkError: iaik.pkcs.pkcs11.wrapper.PKCS11Implementation.initializeLibrary()V [symbol: Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_initializeLibrary or Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_initializeLibrary__]
at com.oracle.svm.jni.access.JNINativeLinkage.getOrFindEntryPoint(JNINativeLinkage.java:153)
at com.oracle.svm.jni.JNIGeneratedMethodSupport.nativeCallAddress(JNIGeneratedMethodSupport.java:57)
at iaik.pkcs.pkcs11.wrapper.PKCS11Implementation.initializeLibrary(PKCS11Implementation.java)
... 2 more
````
