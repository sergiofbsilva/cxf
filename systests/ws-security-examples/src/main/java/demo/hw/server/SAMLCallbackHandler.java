/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package demo.hw.server;
import com.google.common.collect.ImmutableList;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collections;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.bean.AttributeBean;
import org.apache.wss4j.common.saml.bean.AttributeStatementBean;
import org.apache.wss4j.common.saml.bean.KeyInfoBean;
import org.apache.wss4j.common.saml.bean.KeyInfoBean.CERT_IDENTIFIER;
import org.apache.wss4j.common.saml.bean.SubjectBean;
import org.apache.wss4j.common.saml.bean.Version;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableList;

public class SAMLCallbackHandler implements CallbackHandler {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(SAMLCallbackHandler.class);
    
    private String username;

    public SAMLCallbackHandler(String username) {
        this.username = username;
    }

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        LOGGER.info("inside handle");
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof SAMLCallback) {
                LOGGER.info("inside saml handler");
                SAMLCallback callback = (SAMLCallback) callbacks[i];
                callback.setSamlVersion(Version.SAML_20);

                callback.setIssuer("http://localhost:9000/helloWorld");
                String subjectName = this.username;
                String subjectQualifier = "sapID";

                SubjectBean subjectBean =
                        new SubjectBean(
                                subjectName, subjectQualifier, SAML2Constants.CONF_HOLDER_KEY);

                try {
                    KeyInfoBean keyInfo = createKeyInfo();
                    subjectBean.setKeyInfo(keyInfo);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                callback.setSubject(subjectBean);

                AttributeStatementBean attrBean = new AttributeStatementBean();
                attrBean.setSubject(subjectBean);
                
                AttributeBean attributeBean = new AttributeBean();
                attributeBean.setQualifiedName("subject-role");
                attributeBean.setAttributeValues(ImmutableList.<Object>of("system-user"));
                attrBean.setSamlAttributes(Collections.singletonList(attributeBean));
                callback.setAttributeStatementData(Collections.singletonList(attrBean));
                
//                try {
//                    String file = "alice.properties";
//                    Crypto crypto = CryptoFactory.getInstance(file);
//                    callback.setIssuerCrypto(crypto);
//                    callback.setIssuerKeyName("alice");
//                    callback.setIssuerKeyPassword("password");
//                    callback.setSignAssertion(true);
//                    callback.setSignatureAlgorithm(SPConstants.RSA_SHA256);
//                    callback.setSignatureDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256);
//                } catch (WSSecurityException e) {
//                    throw new IOException(e);
//                }
            }
        }
    }

    private KeyInfoBean createKeyInfo() throws Exception {
        Crypto crypto =
            CryptoFactory.getInstance("alice.properties");
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("alice");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);

        KeyInfoBean keyInfo = new KeyInfoBean();
        keyInfo.setCertificate(certs[0]);
        keyInfo.setCertIdentifer(CERT_IDENTIFIER.X509_CERT);

        return keyInfo;
    }
}
