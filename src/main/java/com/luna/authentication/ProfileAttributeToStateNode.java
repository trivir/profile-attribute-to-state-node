/*
 *
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
 * Copyright 2018 David Luna.
 *
 */

package com.luna.authentication;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.sm.DNMapper;
import com.sun.identity.sm.RequiredValueValidator;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.utils.CrestQuery;

import javax.inject.Inject;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * A node that copies a value from a user's profile attributes into a value in their authentication shared state.
 */
@Node.Metadata(outcomeProvider  = SingleOutcomeNode.OutcomeProvider.class,
               configClass      = ProfileAttributeToStateNode.Config.class)
public class ProfileAttributeToStateNode extends SingleOutcomeNode {

    private final Config config;
    private final CoreWrapper coreWrapper;

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100, validators = {RequiredValueValidator.class})
        default Map<String, String> keys() { return Collections.emptyMap(); }

        @Attribute(order = 300, validators = {RequiredValueValidator.class})
        default SelectType selectType() { return SelectType.SelectFirst; }
    }

    /**
     * Create the node.
     *
     * @param config The service config.
     * @param coreWrapper The coreWrapper.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public ProfileAttributeToStateNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        verifyUsernameAndRealm(context);

        JsonValue sharedState = context.sharedState.copy();

        for (Map.Entry<String, String> entry : config.keys().entrySet()) {
            Set value;
            String storageLocation = entry.getValue();

            try {
                value = getValueForKeyFromProfile(entry.getKey(), context);
            } catch (IdRepoException | SSOException e) {
                throw new NodeProcessException("Error retrieving value from user's profile.");
            }

            Object selectedValue;

            switch (config.selectType()) {
                case SelectFirst:
                    if (!value.iterator().hasNext()) {
                        selectedValue = null;
                    } else {
                        selectedValue = value.iterator().next();
                    }
                    break;
                case SelectAsString:
                    selectedValue = value.toString();
                    break;
                case SelectExact:
                default:
                    selectedValue = value;
                    break;
            }
            sharedState.put(storageLocation, selectedValue);
        }

        return goToNext().replaceSharedState(sharedState).build();
    }

    private void verifyUsernameAndRealm(TreeContext context) throws NodeProcessException {
        if (context.sharedState.get(USERNAME).isNull() || context.sharedState.get(REALM).isNull()) {
            throw new NodeProcessException("Username and realm must be selected.");
        }
    }

    private Set getValueForKeyFromProfile(String key, TreeContext context) throws IdRepoException, SSOException {
        AMIdentity user = getIdentity(context.sharedState.get(USERNAME).asString(),
                context.sharedState.get(REALM).asString());
        return user.getAttribute(key);
    }

    private AMIdentity getIdentity(String username, String realm) throws IdRepoException, SSOException {
        AMIdentityRepository idrepo = coreWrapper.getAMIdentityRepository(
                DNMapper.orgNameToDN(realm));
        IdSearchControl idSearchControl = new IdSearchControl();
        idSearchControl.setAllReturnAttributes(true);

        IdSearchResults idSearchResults = idrepo.searchIdentities(IdType.USER,
                new CrestQuery(username), idSearchControl);
        return (AMIdentity) idSearchResults.getSearchResults().iterator().next();
    }

    /**
     * Enum representing various selecting approaches.
     */
    public enum SelectType {
        SelectExact,
        SelectFirst,
        SelectAsString
    }
}