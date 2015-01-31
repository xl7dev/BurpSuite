/**
 * Copyright (c) 2012 centeractive ag. All Rights Reserved.
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.centeractive.ws.common;

import java.io.File;
import java.io.IOException;

/**
 * This class was taken from Axis2 code. It's a Wsdl11Writer dependency.
 *
 * @author Tom Bujok
 * @since 1.0.0
 */
class FileWriter {

    /**
     * Creates/ returns a file object
     *
     * @param rootLocation - Location to be written
     * @param packageName  - package, can be '.' separated
     * @param fileName     name of the file
     * @param extension    type of the file, java, cpp etc
     * @return the File that was created
     * @throws java.io.IOException
     * @throws Exception
     */
    public File createClassFile(File rootLocation, String packageName, String fileName, String extension) throws IOException,
            Exception {
        File returnFile = null;
        File root = rootLocation;

        if (packageName != null) {
            String directoryNames[] = packageName.split("\\.");
            File tempFile = null;
            int length = directoryNames.length;
            for (int i = 0; i < length; i++) {
                tempFile = new File(root, directoryNames[i]);
                root = tempFile;
                if (!tempFile.exists()) {
                    tempFile.mkdir();
                }
            }
        }

        if ((extension != null) && !fileName.endsWith(extension)) {
            fileName = fileName + extension;
        }

        returnFile = new File(root, fileName);
        if (!returnFile.exists()) {
            // returnFile.createNewFile();
        }
        return returnFile;
    }


}
