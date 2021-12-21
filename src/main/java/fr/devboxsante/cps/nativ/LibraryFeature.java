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
