package com.wso2.jwt.extendedjwtbearergranthandler;


import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.XMLObject;
import org.w3c.dom.NodeList;
import org.wso2.carbon.apimgt.keymgt.ScopesIssuer;
import org.wso2.carbon.apimgt.keymgt.handlers.ResourceConstants;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.PermissionsAndRoleConfig;
import org.wso2.carbon.identity.application.common.model.RoleMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.grant.jwt.JWTBearerGrantHandler;
import org.wso2.carbon.identity.oauth2.grant.jwt.JWTConstants;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.application.common.model.*;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.saml.SAML2BearerGrantHandler;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;


import java.text.ParseException;
import java.util.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;






public class ExtendedJWTBearerGrantHandler extends JWTBearerGrantHandler {
    private static Log log = LogFactory.getLog(ExtendedJWTBearerGrantHandler.class);
    IdentityProvider identityProvider =null;
    @Override
        public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx){
        ArrayList<String> list=new ArrayList<String>();

       // String jwtissuer=getJWTIssuer(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters())

        SignedJWT signedJWT = null;
        JWTClaimsSet claimsSet = null;
        //The assertion is not an encrypted one.
        try {
            signedJWT = getSignedJWT(tokReqMsgCtx);
        } catch (IdentityOAuth2Exception e) {
            e.printStackTrace();
        }
        if (signedJWT == null) {
            log.error("No Valid Assertion was found for " + JWTConstants.OAUTH_JWT_BEARER_GRANT_TYPE);
        } else {
            try {
                claimsSet = getClaimSet(signedJWT);
            } catch (IdentityOAuth2Exception e) {
                e.printStackTrace();
            }
        }

        String jwtIssuer = claimsSet.getIssuer();

        String tenantDomain = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getTenantDomain();

        try {
            identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);

        }catch (IdentityProviderManagementException e){
            log.error("message");

        }

        System.out.println(tokReqMsgCtx);
        AuthenticatedUser user = tokReqMsgCtx.getAuthorizedUser();
        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();

        for (Iterator<Map.Entry<ClaimMapping, String>> iterator = userAttributes.entrySet()
                .iterator(); iterator.hasNext(); ) {

            Map.Entry<ClaimMapping, String> entry = iterator.next();
            if(identityProvider.getClaimConfig().getRoleClaimURI()
                    .equals(entry.getKey().getLocalClaim().getClaimUri()) && StringUtils
                    .isNotBlank(entry.getValue())) {

                // IdentityProvider identityProvider = getIdentityProvider(assertion, tenantDomain);
                String updatedRoleClaimValue = getUpdatedRoleClaimValue(identityProvider,
                        entry.getValue());
                if (updatedRoleClaimValue != null) {
                    entry.setValue(updatedRoleClaimValue);
                } else {
                    iterator.remove();
                }
                break;
            }
        }

        return ScopesIssuer.getInstance().setScopes(tokReqMsgCtx);
    }

    public String getJWTIssuer(){

        return "";
    }

    private String getUpdatedRoleClaimValue(IdentityProvider identityProvider, String currentRoleClaimValue) {

        if (StringUtils.equalsIgnoreCase(IdentityApplicationConstants.RESIDENT_IDP_RESERVED_NAME, identityProvider
                .getIdentityProviderName())) {
            return currentRoleClaimValue;
        }
        currentRoleClaimValue=currentRoleClaimValue.replace("\"","")
                .replace("[","").replace("]","");

        PermissionsAndRoleConfig permissionAndRoleConfig = identityProvider.getPermissionAndRoleConfig();
        if (permissionAndRoleConfig != null && ArrayUtils.isNotEmpty(permissionAndRoleConfig.getRoleMappings())) {

            String[] receivedRoles = currentRoleClaimValue.split(FrameworkUtils.getMultiAttributeSeparator());
            List<String> updatedRoleClaimValues = new ArrayList<String>();
            loop:
            for (String receivedRole : receivedRoles) {
                for (RoleMapping roleMapping : permissionAndRoleConfig.getRoleMappings()) {
                    if (roleMapping.getRemoteRole().equals(receivedRole)) {
                        updatedRoleClaimValues.add(roleMapping.getLocalRole().getLocalRoleName());
                        continue loop;
                    }
                }
                if (!OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
                    updatedRoleClaimValues.add(receivedRole);
                }
            }
            if (!updatedRoleClaimValues.isEmpty()) {
                return StringUtils.join(updatedRoleClaimValues, FrameworkUtils.getMultiAttributeSeparator());
            }
            return null;
        }
        if (!OAuthServerConfiguration.getInstance().isReturnOnlyMappedLocalRoles()) {
            return currentRoleClaimValue;
        }
        return null;
    }


    private JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        JWTClaimsSet claimsSet = null;
        try {
            claimsSet = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            log.error("Error when trying to retrieve claimsSet from the JWT");
        }
        return claimsSet;
    }

    private SignedJWT getSignedJWT(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        RequestParameter[] params = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();
        String assertion = null;
        SignedJWT signedJWT;
        for (RequestParameter param : params) {
            if (param.getKey().equals(JWTConstants.OAUTH_JWT_ASSERTION)) {
                assertion = param.getValue()[0];
                break;
            }
        }
        if (StringUtils.isEmpty(assertion)) {
            return null;
        }

        try {
            signedJWT = SignedJWT.parse(assertion);
            if (log.isDebugEnabled()) {
             //   logJWT(signedJWT);
            }
        } catch (ParseException e) {
            String errorMessage = "Error while parsing the JWT.";
            throw new IdentityOAuth2Exception(errorMessage, e);
        }
        return signedJWT;
    }

}
