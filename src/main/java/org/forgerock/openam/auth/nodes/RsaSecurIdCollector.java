/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.ONE_TIME_PASSWORD;

import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.PasswordCallback;

import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;
import com.google.inject.assistedinject.Assisted;

@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = RsaSecurIdCollector.Config.class,
        tags = {"mfa", "multi-factor authentication"})
public class RsaSecurIdCollector extends SingleOutcomeNode {

    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/RsaSecurIdCollector";
    private final Logger logger = LoggerFactory.getLogger(RsaSecurIdCollector.class);
    private final Config config;

    /**
     * Configuration for the node.
     */
    public interface Config {
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     */
    @Inject
    public RsaSecurIdCollector(@Assisted Config config) {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        logger.debug("RsaSecurIdCollector started");
        return context.getCallback(PasswordCallback.class)
                      .map(PasswordCallback::getPassword)
                      .map(String::new)
                      .filter(password -> !Strings.isNullOrEmpty(password))
                      .map(password -> savePassword(context, password))
                      .orElseGet(() -> collectPassword(context));
    }

    private Action savePassword(TreeContext context, String password) {
        context.transientState.put(ONE_TIME_PASSWORD, password);
        return goToNext().build();
    }

    private Action collectPassword(TreeContext context) {
        ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        return send(new PasswordCallback(bundle.getString("callback.password"), false)).build();
    }

}
