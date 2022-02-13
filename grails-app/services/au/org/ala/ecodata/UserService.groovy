package au.org.ala.ecodata

import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.userdetails.UserDetailsFromIdListRequest
import com.squareup.moshi.Moshi
import com.squareup.moshi.Rfc3339DateJsonAdapter
import grails.core.GrailsApplication
import grails.plugin.cache.Cacheable
import okhttp3.OkHttpClient

import javax.annotation.PostConstruct

import static java.util.concurrent.TimeUnit.MILLISECONDS

class UserService {

    static transactional = false
    WebService webService
    GrailsApplication grailsApplication
    UserService userService
    UserDetailsClient userDetailsClient

    /** Limit to the maximum number of Users returned by queries */
    static final int MAX_QUERY_RESULT_SIZE = 1000

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
        getUserForUserId(userId, true)?.roles ?: []
    }

    def userInRole(Object role){
        return authService.userInRole(role)
    }

    @Cacheable("userDetailsCache")
    synchronized def getUserForUserId(String userId, boolean includeProps = true) {
        if (!userId) return null // this would have failed anyway
        def call = userDetailsClient.getUserDetails(userId, includeProps)
        try {
            def response = call.execute()
            if (response.successful) {
                return response.body()
            } else {
                log.warn("Failed to retrieve user details for userId: $userId, includeProps: $includeProps. Error was: ${response.message()}")
            }
        } catch (Exception ex) {
            log.error("Exception caught trying get find user details for $userId.", ex)
        }
        return null
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
        webService.doPostWithParams(grailsApplication.config.authGetKeyUrl, [userName: username, password: password], true)
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

    @Cacheable("userDetailsByIdCache")
    def getUserDetailsById(List<String> userIds, boolean includeProps = true) {
        def call = userDetailsClient.getUserDetailsFromIdList(new UserDetailsFromIdListRequest(userIds, includeProps))
        try {
            def response = call.execute()
            if (response.successful) {
                return response.body()
            } else {
                log.warn("Failed to retrieve user details. Error was: ${response.message()}")
            }
        } catch (Exception e) {
            log.error("Exception caught retrieving userdetails for ${userIds}", e)
        }
        return null
    }
}
