package au.org.ala.ecodata

import au.org.ala.web.AlaSecured
import au.org.ala.web.AuthService
import au.org.ala.ws.security.client.AlaOidcClient
import grails.converters.JSON
import grails.core.support.GrailsConfigurationAware
import grails.util.Environment
import grails.web.http.HttpHeaders
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.util.FindBest
import org.pac4j.jee.context.JEEContextFactory
import org.springframework.beans.factory.annotation.Autowired

import javax.servlet.http.HttpServletRequest

class ApiKeyInterceptor implements GrailsConfigurationAware {
    static String httpRequestHeaderForUserId
    ProjectService projectService
    ProjectActivityService projectActivityService
    UserService userService
    PermissionService permissionService
    CommonService commonService
    ActivityService activityService
    @Autowired(required = false)
    AlaOidcClient alaOidcClient
    @Autowired(required = false)
    Config config
    AuthService authService

    def LOCALHOST_IP = '127.0.0.1'

    public ApiKeyInterceptor() {
        matchAll().excludes(controller: 'graphql')
    }

    boolean before() {
        def controller = grailsApplication.getArtefactByLogicalPropertyName("Controller", controllerName)
        Class controllerClass = controller?.clazz
        def method = controllerClass?.getMethod(actionName?:"index", [] as Class[])
        Map result = [error: '', status : 401]

        if (controllerClass?.isAnnotationPresent(PreAuthorise) || method?.isAnnotationPresent(PreAuthorise)) {
            // What rules needs to be satisfied?
            PreAuthorise pa = method.getAnnotation(PreAuthorise) ?: controllerClass.getAnnotation(PreAuthorise)

            if (pa.basicAuth()) {
                String userId
                request.userId = userId = userService.getUserIdFromJWT()

                // will be switched off when cognito migration is complete
                if (grailsApplication.config.getProperty('authkey.check', Boolean, false) && !userId) {
                    userId = request.userId = userService.authorize(request.getHeader('userName'), request.getHeader('authKey'))
                }

                if (userId) {
                    userService.setUser(false, userId)
                }

                if(permissionService.isUserAlaAdmin(request.userId)) {
                    /* Don't enforce check for ALA admin.*/
                }
                else if (request.userId) {
                    String accessLevel = pa.accessLevel()
                    String idType = pa.idType()
                    String entityId = params[pa.id()]

                    if (accessLevel && idType) {

                        switch (idType) {
                            case "organisationId":
                                result = permissionService.checkPermission(accessLevel, entityId, Organisation.class.name, request.userId)
                                break
                            case "projectId":
                                result = permissionService.checkPermission(accessLevel, entityId, Project.class.name, request.userId)
                                break
                            case "projectActivityId":
                                def pActivity = projectActivityService.get(entityId)
                                request.projectId = pActivity?.projectId
                                result = permissionService.checkPermission(accessLevel, pActivity?.projectId, Project.class.name, request.userId)
                                break
                            case "activityId":
                                def activity = activityService.get(entityId,'flat')
                                result = permissionService.checkPermission(accessLevel, activity?.projectId, Project.class.name, request.userId)
                                break
                            default:
                                break
                        }
                    }

                } else {
                    result.error = "Access denied"
                    result.status = 401
                }
            }

        } else {

            // Allow migration to the AlaSecured annotation.
            if (!controllerClass?.isAnnotationPresent(AlaSecured) && !method?.isAnnotationPresent(AlaSecured)) {
                List whiteList = buildWhiteList()
                List clientIp = getClientIP(request)
                boolean ipOk = checkClientIp(clientIp, whiteList)

                // All request without PreAuthorise annotation needs to be secured by IP for backward compatibility
                if (!ipOk) {
                    log.warn("Non-authorised IP address - ${clientIp}" )
                    result.status = 403
                    result.error = "not authorised"
                }
                else {
                    userService.setUser(true)
                }

                // Support RequireApiKey on top of ip restriction.
                if(controllerClass?.isAnnotationPresent(RequireApiKey) || method?.isAnnotationPresent(RequireApiKey)){
                    boolean valid = false
                    String token = request.getHeader('Authorization')
                    if (isFunctionalTest()) {
                        valid = true
                    }
                    else if (token?.startsWith('Bearer')) {
                        WebContext context = FindBest.webContextFactory(null, config, JEEContextFactory.INSTANCE).newContext(request, response)
                        SessionStore sessionStore = config.sessionStore
                        Optional credentialOpt = alaOidcClient.retrieveCredentials(context, sessionStore)
                        Credentials credentials = credentialOpt.get()
                        valid = credentials ? true : false
                    }
                    else if (grailsApplication.config.getProperty('security.apikey.enabled', Boolean, false)) {
                        def keyOk = commonService.checkApiKey(token).valid
                        valid = keyOk
                    }

                    if (!valid) {
                        log.warn("No valid JWT or api key for ${controllerName}/${actionName}")
                        result.status = 403
                        result.error = "not authorised"
                    }
                }
            }
            else {
                userService.setUser(false)
            }
        }

        if(result.error) {
            response.status = result.status
            render result as JSON
            return false
        }
        true
    }

    boolean after() { true }

    void afterView() {
        userService.clearCurrentUser()
    }

    /**
     * Client IP passes if it is in the whitelist of if the whitelist is empty apart from localhost.
     * @param clientIp
     * @return
     */
    boolean checkClientIp(List clientIps, List whiteList) {
        clientIps.size() > 0 && whiteList.containsAll(clientIps) || (whiteList.size() == 1 && whiteList[0] == LOCALHOST_IP)
    }

    @Override
    void setConfiguration(grails.config.Config co) {
        httpRequestHeaderForUserId = co.getProperty('app.http.header.userId', String)
    }

    boolean isFunctionalTest() {
        Environment.current.name == "meritfunctionaltest"
    }

    private List buildWhiteList() {
        def whiteList = [LOCALHOST_IP] // allow calls from localhost to make testing easier
        def config = grailsApplication.config.getProperty('app.api.whiteList')
        if (config) {
            whiteList.addAll(config.split(',').collect({it.trim()}))
        }
        whiteList
    }

    private List getClientIP(HttpServletRequest request) {
        // External requests to ecodata are proxied by Apache, which uses X-Forwarded-For to identify the original IP.
        // From grails 5, tomcat started returning duplicate headers as a comma separated list.  When a download
        // request is sent from MERIT to ecodata, ngnix adds a X-Forwarded-For header, then forwards to the
        // reporting server, which adds another header before proxying to tomcat/grails.
        List allIps = []
        Enumeration<String> ips = request.getHeaders(HttpHeaders.X_FORWARDED_FOR)
        while (ips.hasMoreElements()) {
            String ip = ips.nextElement()
            allIps.addAll(ip?.split(',').collect{it?.trim()})
        }
        allIps.add(request.getRemoteHost())
        return allIps
    }

}
