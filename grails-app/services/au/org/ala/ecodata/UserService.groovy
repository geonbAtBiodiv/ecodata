package au.org.ala.ecodata

import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.web.AuthService
import au.org.ala.ws.security.authenticator.AlaOidcAuthenticator
import au.org.ala.ws.security.client.AlaOidcClient
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import grails.core.GrailsApplication
import org.grails.web.servlet.mvc.GrailsWebRequest
import org.pac4j.core.config.Config
import org.pac4j.core.exception.CredentialsException
import org.springframework.beans.factory.annotation.Autowired

import javax.servlet.http.HttpServletRequest
import java.text.ParseException

class UserService {

    static transactional = false
    AuthService authService
    WebService webService
    GrailsApplication grailsApplication
    UserDetailsClient userDetailsClient
    @Autowired(required = false)
    AlaOidcClient alaOidcClient
    @Autowired(required = false)
    Config config

    /** Limit to the maximum number of Users returned by queries */
    static final int MAX_QUERY_RESULT_SIZE = 1000
    static String AUTHORIZATION_HEADER_FIELD = "Authorization"

    private static ThreadLocal<UserDetails> _currentUser = new ThreadLocal<UserDetails>()

    def getCurrentUserDisplayName() {
        String displayName = authService.displayName
        if (!displayName) {
            def currentUser = _currentUser.get()
            displayName = currentUser ? currentUser.displayName : ""
        }

        displayName
    }

    /**
     * Static equivalent of getCurrentUserDetails for use by GORM objects when dependency injection
     * is disabled in grails 3.
     */
    static def currentUser() {
        return _currentUser.get()
    }

    def getCurrentUserDetails() {
        return _currentUser.get()
    }

    def lookupUserDetails(String userId) {

        def userDetails = getUserForUserId(userId)
        if (!userDetails) {
            if (log.debugEnabled) {
                log.debug("Unable to lookup user details for userId: ${userId}")
            }
            userDetails = new UserDetails(userId: userId, userName: 'unknown', displayName: 'Unknown')
        }

        userDetails
    }

    /**
     * Gets the CAS roles for the specified user. If no id is provided, then the currently authenticated user will be used
     *
     * @param userId The ID of the user whose roles you want to retrieve. Optional - if not provided, will return the roles for the currently authenticated user (if there is one)
     * @return List of {@link au.org.ala.web.CASRoles} names
     */
    def getRolesForUser(String userId = null) {
        userId = userId ?: getCurrentUserDetails().userId
        authService.getUserForUserId(userId, true)?.roles ?: []
    }

    def userInRole(Object role){
        return authService.userInRole(role)
    }

    synchronized def getUserForUserId(String userId) {
        if (!userId) {
            return null
        }
        return authService.getUserForUserId(userId)
    }

    /**
     * This method gets called by a filter at the beginning of the request (if a userId parameter is on the URL)
     * It sets the user details in a thread local for extraction by the audit service.
     * @param userId
     */
    def setCurrentUser(String userId) {

        def userDetails = lookupUserDetails(userId)
        if (userDetails) {
            _currentUser.set(userDetails)
            return userDetails
        } else {
            log.warn("Failed to lookup user details for user id ${userId}! No details set on thread local.")
        }
    }

    def clearCurrentUser() {
        if (_currentUser) {
            _currentUser.remove()
        }
    }

    /**
     * Check username against the auth key.
     *
     * @param username
     * @param authKey
     */
    String authorize(userName, authKey) {
        String userId = ""

        if (authKey && userName) {
            String key = new String(authKey)
            String username = new String(userName)

            def url = grailsApplication.config.getProperty('authCheckKeyUrl')
            def params = [userName: username, authKey: key]
            def result = webService.doPostWithParams(url, params, true)
            if (!result?.resp?.statusCode && result.resp?.status == 'success') {
                // We are deliberately using getUserForUserId over lookupUserDetails as we don't
                // want the fallback if the lookup fails.
                def userDetails = getUserForUserId(username)
                userId = userDetails?.userId
            }
        }

        return userId
    }

    /**
     * Get auth key for the given username and password
     *
     * @param username
     * @param password
     */
    def getUserKey(String username, String password) {
        webService.doPostWithParams(grailsApplication.config.getProperty('authGetKeyUrl'), [userName: username, password: password], true)
    }

    /**
     * Convenience method to record the most recent time a user has logged into a hub.
     * If no User exists, one will be created.  If no login record exists for a hub, one
     * will be added.  If an existing login time exists, the date will be updated.
     */
    User recordUserLogin(String hubId, String userId, Date loginTime = new Date()) {

        if (!hubId || !userId || !Hub.findByHubId(hubId)) {
            throw new IllegalArgumentException()
        }

        User user = User.findByUserIdAndStatusNotEqual(userId, Status.DELETED)
        if (!user) {
            user = new User(userId:userId)
        }
        user.loginToHub(hubId, loginTime)
        user.save()

        user
    }

    /**
     * Returns a list of Users who last logged into the specified hub before the supplied date.
     * Users who have never logged into the hub will not be returned.
     * @param hubId The hubId of the hub of interest
     * @param date The cutoff date for logins
     * @param offset (optional, default 0) offset into query results, used for batching
     * @param max (optional, maximum 1000) maximum number of results to return from the query
     * @return List<User>
     */
    List<User> findUsersNotLoggedInToHubSince(String hubId, Date date, int offset = 0, int max = MAX_QUERY_RESULT_SIZE) {
        Map options = [offset:offset, max: Math.min(max, MAX_QUERY_RESULT_SIZE), sort:'userId']

        User.where {
            userHubs {
                hubId == hubId && lastLoginTime < date
            }
        }.list(options)
    }

    /**
     * Returns a list of Users who last logged into the specified between two specified dates.
     * Users who have never logged into the hub will not be returned.
     * @param hubId The hubId of the hub of interest
     * @param fromDate The start date for finding logins
     * @param toDate The end date for finding logins
     * @param offset (optional, default 0) offset into query results, used for batching
     * @param max (optional, maximum 1000) maximum number of results to return from the query
     * @return List<User> The users who need to be sent a warning.
     */
    List<User> findUsersWhoLastLoggedInToHubBetween(String hubId, Date fromDate, Date toDate, int offset = 0, int max = MAX_QUERY_RESULT_SIZE) {
        Map options = [offset:offset, max: Math.min(max, MAX_QUERY_RESULT_SIZE), sort:'userId']
        User.where {
            userHubs {
                hubId == hubId && lastLoginTime < toDate && lastLoginTime >= fromDate
            }
        }.list(options)
    }

    /**
     * This will return the User entity
     */
    User findByUserId(String userId) {
        User.findByUserId(userId)
    }

    String getUserIdFromJWT(String authorizationHeader = null) {
        if((config == null) || (alaOidcClient == null))
            return

        GrailsWebRequest grailsWebRequest = GrailsWebRequest.lookup()
        HttpServletRequest request = grailsWebRequest.getCurrentRequest()
        if (!authorizationHeader)
            authorizationHeader = request?.getHeader(AUTHORIZATION_HEADER_FIELD)

        if (authorizationHeader?.startsWith("Bearer")) {
            final JWT jwt
            try {
                jwt = JWTParser.parse(authorizationHeader.replace("Bearer ", ""))
            } catch (ParseException e) {
                throw new CredentialsException("Cannot decrypt / verify JWT", e)
            }

            // Create a JWT processor for the access tokens
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<SecurityContext>()

            // Configure the JWT processor with a key selector to feed matching public
            // RSA keys sourced from the JWK set URL
            AlaOidcAuthenticator authenticator = alaOidcClient.authenticator
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<SecurityContext>(authenticator.expectedJWSAlgs, authenticator.keySource)
            jwtProcessor.setJWSKeySelector(keySelector)

            // Set the required JWT claims for access tokens issued by the server
            // TODO externalise the required claims
            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier(new JWTClaimsSet.Builder().issuer(authenticator.issuer.getValue()).build(), Set.copyOf(authenticator.requiredClaims)))

            try {
                JWTClaimsSet claimsSet = jwtProcessor.process(jwt, null)
                return (String) claimsSet.getClaim(authenticator.userIdClaim)
            } catch (BadJOSEException e) {
                return null
            } catch (JOSEException e) {
                return null
            }
        }
    }

    void setUser(boolean trustHeader = false, String userId = null) {
        GrailsWebRequest grailsWebRequest = GrailsWebRequest.lookup()
        HttpServletRequest request = grailsWebRequest.getCurrentRequest()

        // userId is set from either the request param userId or failing that it tries to get it from
        // the UserPrincipal (assumes ecodata is being accessed directly via admin page)
        userId = userId ?: authService.getUserId()
        if (!userId && trustHeader) {
            userId = request.getHeader(ApiKeyInterceptor.httpRequestHeaderForUserId)
        }

        if (userId) {
            def userDetails = setCurrentUser(userId)
            if (userDetails) {
                // We set the current user details in the request scope because
                // the 'afterView' hook can be called prior to the actual rendering (despite the name)
                // and the thread local can get clobbered before it is actually required.
                // Consumers who have access to the request can simply extract current user details
                // from there rather than use the service.
                request.setAttribute(UserDetails.REQUEST_USER_DETAILS_KEY, userDetails)
            }
        }
    }
}
