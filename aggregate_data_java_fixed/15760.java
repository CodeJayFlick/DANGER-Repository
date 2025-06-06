/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 * and limitations under the License.
 */
package ai.djl.util;

import ai.djl.util.cuda.CudaUtils;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;

/**
 * The platform contains information regarding the version, os, and build flavor of the MXNet native
 * code.
 */
public final class Platform {

    private String version;
    private String osPrefix;
    private String osArch;
    private String flavor;
    private String cudaArch;
    private String[] libraries;
    private boolean placeholder;

    /** Constructor used only for {@link Platform#fromSystem()}. */
    private Platform() {}

    /**
     * Returns the platform that parsed from "engine".properties file.
     *
     * @param url the url to the "engine".properties file
     * @return the platform that parsed from mxnet.properties file
     * @throws IOException if the file could not be read
     */
    public static Platform fromUrl(URL url) throws IOException {
        Platform platform = Platform.fromSystem();
        try (InputStream conf = url.openStream()) {
            Properties prop = new Properties();
            prop.load(conf);
            // 1.6.0 later should always has version property
            platform.version = prop.getProperty("version");
            if (platform.version == null) {
                throw new IllegalArgumentException(
                        "version key is required in <engine>.properties file.");
            }
            platform.placeholder = prop.getProperty("placeholder") != null;
            String flavorPrefixedClassifier = prop.getProperty("classifier", "");
            String libraryList = prop.getProperty("libraries", "");
            if (libraryList.isEmpty()) {
                platform.libraries = new String[0];
            } else {
                platform.libraries = libraryList.split(",");
            }

            if (!flavorPrefixedClassifier.isEmpty()) {
                String[] tokens = flavorPrefixedClassifier.split("-");
                platform.flavor = tokens[0];
                platform.osPrefix = tokens[1];
                platform.osArch = tokens[2];
            }
        }
        return platform;
    }

    /**
     * Returns the platform for the current system with the specified version.
     *
     * @param version the engine version
     * @return the platform for the current system
     */
    public static Platform fromSystem(String version) {
        Platform platform = fromSystem();
        platform.version = version;
        return platform;
    }

    /**
     * Returns the platform for the current system.
     *
     * @return the platform for the current system
     */
    public static Platform fromSystem() {
        Platform platform = new Platform();
        String osName = System.getProperty("os.name");
        if (osName.startsWith("Win")) {
            platform.osPrefix = "win";
        } else if (osName.startsWith("Mac")) {
            platform.osPrefix = "osx";
        } else if (osName.startsWith("Linux")) {
            platform.osPrefix = "linux";
        } else {
            throw new AssertionError("Unsupported platform: " + osName);
        }
        platform.osArch = System.getProperty("os.arch");
        if ("amd64".equals(platform.osArch)) {
            platform.osArch = "x86_64";
        }
        if (CudaUtils.getGpuCount() > 0) {
            platform.flavor = "cu" + CudaUtils.getCudaVersionString();
            platform.cudaArch = CudaUtils.getComputeCapability(0);
        } else {
            platform.flavor = "cpu";
        }
        return platform;
    }

    /**
     * Returns the Engine version.
     *
     * @return the Engine version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Returns the os (win, osx, or linux).
     *
     * @return the os (win, osx, or linux)
     */
    public String getOsPrefix() {
        return osPrefix;
    }

    /**
     * Returns the os architecture (x86_64, aar64, etc).
     *
     * @return the os architecture (x86_64, aar64, etc)
     */
    public String getOsArch() {
        return osArch;
    }

    /**
     * Returns the MXNet build flavor.
     *
     * @return the MXNet build flavor
     */
    public String getFlavor() {
        return flavor;
    }

    /**
     * Returns the classifier for the platform.
     *
     * @return the classifier for the platform
     */
    public String getClassifier() {
        return osPrefix + '-' + osArch;
    }

    /**
     * Returns the cuda arch.
     *
     * @return the cuda arch
     */
    public String getCudaArch() {
        return cudaArch;
    }

    /**
     * Returns the libraries used in the platform.
     *
     * @return the libraries used in the platform
     */
    public String[] getLibraries() {
        return libraries;
    }

    /**
     * Returns true if the platform is a placeholder.
     *
     * @return true if the platform is a placeholder
     */
    public boolean isPlaceholder() {
        return placeholder;
    }

    /**
     * Returns true the platforms match (os and flavor).
     *
     * @param system the platform to compare it to
     * @return true if the platforms match
     */
    public boolean matches(Platform system) {
        return matches(system, true);
    }

    /**
     * Returns true the platforms match (os and flavor).
     *
     * @param system the platform to compare it to
     * @param strictModel cuda minor version must match
     * @return true if the platforms match
     */
    public boolean matches(Platform system, boolean strictModel) {
        if (!osPrefix.equals(system.osPrefix) || !osArch.equals(system.osArch)) {
            return false;
        }
        // if system Machine is GPU
        if (system.flavor.startsWith("cu")) {
            // system flavor doesn't contain mkl, but MXNet has: cu110mkl
            return "cpu".equals(flavor)
                    || "mkl".equals(flavor)
                    || flavor.startsWith(system.flavor)
                    || (!strictModel && flavor.compareTo(system.flavor) <= 0);
        }
        return "cpu".equals(flavor) || "mkl".equals(flavor);
    }
}
