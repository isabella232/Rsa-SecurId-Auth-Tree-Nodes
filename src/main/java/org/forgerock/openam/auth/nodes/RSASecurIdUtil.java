package org.forgerock.openam.auth.nodes;

import static org.forgerock.json.JsonValue.json;

import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.util.Function;

public class RSASecurIdUtil {

    protected static final String CLIENT_KEY = "client-key";
    protected static final String CLIENT_ID = "clientId";
    protected static final String SUBJECT_NAME = "subjectName";
    protected static final String CONTEXT = "context";
    protected static final String MESSAGE_ID = "messageId";
    protected static final String ATTEMPT_REASON_CODE = "attemptReasonCode";
    protected static final String AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED";
    protected static final String CHALLENGE = "CHALLENGE";
    protected static final String ATTEMPT_RESPONSE_CODE = "attemptResponseCode";
    protected static final String CHALLENGES = "challenges";
    protected static final String REQUIRED_METHODS = "requiredMethods";
    protected static final String METHOD_ID = "methodId";
    protected static final String SECURID = "SECURID";
    protected static final String AUTHN_ATTEMPT_ID = "authnAttemptId";
    protected static final String SUBJECT_CREDENTIALS = "subjectCredentials";
    protected static final String COLLECTED_INPUTS = "collectedInputs";
    protected static final String NAME = "name";
    protected static final String VALUE = "value";
    protected static final String SUCCESS = "SUCCESS";
    protected static final String CREDENTIAL_VERIFIED = "CREDENTIAL_VERIFIED";
    protected static final String VERIFY_ERROR = "VERIFY_ERROR";
    protected static final String FAIL = "FAIL";
    protected static final String SECURID_NEXT_TOKENCODE = "SECURID_NEXT_TOKENCODE";
    protected static final String IN_RESPONSE_TO = "inResponseTo";
    protected static final String CHALLENGE_METHODS = "challengeMethods";

    static Function<Response, JsonValue, NodeProcessException> mapToJsonValue() {
        return response -> {
            try {
                if (!response.getStatus().isSuccessful()) {
                    throw response.getCause();
                }
                return json(response.getEntity().getJson());
            } catch (Exception e) {
                throw new NodeProcessException("Unable to process request. " + response.getEntity().toString(), e);
            }
        };
    }
}
