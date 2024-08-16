package au.org.ala.ecodata

import au.org.ala.ecodata.converter.ISODateBindingConverter
import com.mongodb.BasicDBObject
import grails.converters.JSON
import grails.test.mongodb.MongoSpec
import grails.testing.gorm.DomainUnitTest
import grails.testing.services.ServiceUnitTest
import org.grails.web.converters.marshaller.json.CollectionMarshaller
import org.grails.web.converters.marshaller.json.MapMarshaller
import spock.lang.Ignore

import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class ProjectServiceSpec extends MongoSpec implements ServiceUnitTest<ProjectService>, DomainUnitTest<Project> {

    ProjectActivityService projectActivityServiceStub = Stub(ProjectActivityService)
    WebService webServiceStub = Stub(WebService)
    SiteService siteService = new SiteService()
    DocumentService documentService = Mock(DocumentService)
    ActivityService activityService = Mock(ActivityService)
    ReportingService reportingService = Mock(ReportingService)
    MetadataService metadataService = Mock(MetadataService)
    LockService lockService = Mock(LockService)

    String collectoryBaseUrl = ''
    String meritDataProvider = 'drMerit'
    String biocollectDataProvider = 'drBiocollect'
    String dataProviderId = 'dp1'
    String dataResourceId = 'dr1'
    int delay = 5000


    def setup() {

        deleteAll()

        defineBeans {
            commonService(CommonService)
            collectoryService(CollectoryService)
            formattedStringConverter(ISODateBindingConverter)
        }

        grailsApplication.config.collectory = [baseURL:collectoryBaseUrl, dataProviderUid:[merit:meritDataProvider, biocollect:biocollectDataProvider], collectoryIntegrationEnabled: true]
        grailsApplication.mainContext.commonService.grailsApplication = grailsApplication
        grailsApplication.mainContext.collectoryService.grailsApplication = grailsApplication
        grailsApplication.mainContext.collectoryService.webService = webServiceStub
        grailsApplication.mainContext.collectoryService.projectService = service
        service.collectoryService = grailsApplication.mainContext.collectoryService
        service.projectActivityService = projectActivityServiceStub
        service.siteService = siteService
        service.activityService = activityService
        service.reportingService = reportingService
        service.documentService = documentService
        service.grailsApplication = grailsApplication
        service.metadataService = metadataService
        service.lockService = lockService
        webServiceStub.doPost(collectoryBaseUrl+"ws/dataResource", _) >> [:]
        webServiceStub.extractIdFromLocationHeader(_) >> dataResourceId
        webServiceStub.doPost(collectoryBaseUrl+"ws/dataResource/"+dataResourceId, _) >> [:]

        JSON.registerObjectMarshaller(new MapMarshaller())
        JSON.registerObjectMarshaller(new CollectionMarshaller())
    }

    def deleteAll() {
        Program.collection.remove(new BasicDBObject())
        Project.collection.remove(new BasicDBObject())
        ManagementUnit.collection.remove(new BasicDBObject())
        AuditMessage.collection.remove(new BasicDBObject())
    }

    def cleanup() {
        Project.findAll().each { it.delete(flush:true) }
        AuditMessage.findAll().each { it.delete(flush:true) }
        UserPermission.findAll().each { it.delete(flush:true) }
        Site.findAll().each { it.delete(flush:true) }
    }

    def "test create and update project"() {
        given:
        def projData = [name:'test proj', description: 'test proj description', dynamicProperty: 'dynamicProperty', isBushfire:true, bushfireCategories: [], alaHarvest: true]
        def updatedData = projData + [description: 'test proj updated description', origin: 'atlasoflivingaustralia']

        def result, projectId, savedProj
        when:
        Project.withNewTransaction {
            result = service.create(projData)
            projectId = result.projectId
            savedProj = isValueCommitted(projectId, 'dataResourceId', dataResourceId)
        }

        then: "ensure the response contains the id of the new project"
        result.status == 'ok'
        projectId != null
        savedProj.name == projData.name
        savedProj.description == projData.description
//        savedProj.dataResourceId == dataResourceId
        savedProj['dynamicProperty'] == projData.dynamicProperty
//        updating on thread not consistently return updated dataResourceId
//        when:"project update with alaHarvest is false should not remove dataResourceId"
//        service.update([alaHarvest: false], projectId)
//        savedProj = isValueCommitted(projectId, 'dataResourceId', dataResourceId)
//
//        then:
//        savedProj.dataResourceId == dataResourceId

//        when:"project update with alaHarvest is true should not create a new dataResourceId"
//        webServiceStub.extractIdFromLocationHeader(_) >> "dr3"
//        service.update([alaHarvest: true], projectId)
//        savedProj = isValueCommitted(projectId, 'dataResourceId', dataResourceId)
//
//        then:
//        savedProj.dataResourceId == dataResourceId

        when:
        Project.withNewTransaction {
            result = service.update(updatedData, projectId)
        }
        then: "ensure the response status is ok and the project was updated"
        result.status == 'ok'


        when: "select the updated project back from the database"
        savedProj = Project.findByProjectId(projectId)


        then: "ensure the unchanged properties are the same as the original"
        savedProj.name == projData.name
        //savedProj['dynamicProperty'] == projData.dynamicProperty  The dbo property on the domain object appears to be missing during unit tests which prevents dynamic properties from being retreived.

        then: "ensure the updated properties are the same as the change"
        savedProj.description == updatedData.description

        then: "categories can be null for tagged bushfire recovery projects"
        savedProj.isBushfire == updatedData.isBushfire
        savedProj.bushfireCategories == updatedData.bushfireCategories

    }

    @Ignore
    static Project isValueCommitted (String projectId, String property, String expected = null) {
        int MAX_CHECK = 60, count = 0, delay = 1000
        Project savedProj

        do {
            count ++
            Project.withSession { session ->
                session.clear()
                savedProj = Project.findByProjectId(projectId)
            }

            if (savedProj?.getAt(property) == expected) {
                return savedProj
            }

            Thread.sleep(delay)
        } while ((count < MAX_CHECK))

        return savedProj
    }

    def "test project validation"() {
        given:
        def projData = [description: 'test proj description', dynamicProperty: 'dynamicProperty']

        when:
        def result = service.create(projData)

        then:
        result.status == 'error'
        result.error != null

    }

    def "Program names will be returned in the ALL view if the project references the program by programId"() {

        setup:
        Project project = new Project(projectId: 'p1', name: "A project", programId: 'program2')
        Program program = new Program(programId: 'program1', name: "Program 1")
        Program child = new Program(programId: 'program2', name: "Child Program", parent: program)
        Project.withTransaction {
            program.save(failOnError: true)
            child.save(failOnError: true)
        }

        project.metaClass.getDbo = { new BasicDBObject(project.properties) }

        when:
        Map result = null
        Project.withTransaction {
            result = service.toMap(project, 'all')
        }

        then:
        result.projectId == project.projectId
        result.name == project.name
        result.programId == project.programId
        result.associatedProgram == program.name
        result.associatedSubProgram == child.name

    }

    def "The project supports Risks as an embedded mapping"() {
        setup:
        String projectId = 'p1-risks'
        Project project = new Project(projectId:projectId, name:"Project")
        Map risks = buildRisksData()

        when:
        Map result
        project.save(flush:true, failOnError: true)
        result = service.update([risks:risks], projectId, false)


        then:
        result == [status:"ok"]

        when:
        Project project2 = Project.findByProjectId(projectId)

        then:
        project2.risks.overallRisk == risks.overallRisk
        project2.risks.dateUpdated ==  DateUtil.parse(risks.dateUpdated)
        project2.risks.rows.size() == risks.rows.size()
        int i=0
        for (Risk risk : project2.risks.rows) {
            risk.consequence == risks.rows[i].consequence
            risk.likelihood == risks.rows[i].consequence
            risk.residualRisk == risks.rows[i].consequence
            risk.currentControl == risks.rows[i].consequence
            risk.description == risks.rows[i].consequence
            risk.threat == risks.rows[i].consequence
            risk.riskRating == risks.rows[i].consequence
            i++
        }
    }

    def "The project supports an associatedOrgs embedded mapping when updating the project"() {
        setup:
        String projectId = 'p1'
        Project project = new Project(projectId:projectId, name:"Project", externalId:'e1')

        when:
        Map result
        project.save(flush:true, failOnError: true)
        result = service.update([associatedOrgs:[[organisationId:'o1', name:"Test name", logo:"test logo", url:"test url"]]], projectId, false)

        then:
        result == [status:"ok"]

        when:
        Project project2 = Project.findByProjectId(projectId)

        then:
        project2.name == "Project"
        project2.externalId == "e1"
        project2.associatedOrgs[0].organisationId == "o1"
        project2.associatedOrgs[0].name == "Test name"
        project2.associatedOrgs[0].logo == "test logo"
        project2.associatedOrgs[0].url == "test url"

    }

    def "The project supports an associatedOrgs embedded mapping when creating a project"() {
        setup:
        Map props = [name:"Project", externalId:'e1', associatedOrgs:[[organisationId:'o1', name:"Test name", logo:"test logo", url:"test url"]]]

        when:
        Map result = service.create(props)

        then:
        result.status == "ok"

        when:
        Project project2 = Project.findByProjectId(result.projectId)

        then:
        project2.name == "Project"
        project2.externalId == "e1"
        project2.associatedOrgs[0].organisationId == "o1"
        project2.associatedOrgs[0].name == "Test name"
        project2.associatedOrgs[0].logo == "test logo"
        project2.associatedOrgs[0].url == "test url"

    }

    def "The project supports an externalIds embedded mapping when updating a project"() {
        setup:
        Map externalIds = [externalIds:[
                [idType:'INTERNAL_ORDER_NUMBER', externalId: 'internalOrderNumber1'],
                [idType:'INTERNAL_ORDER_NUMBER', externalId: 'internalOrderNumber2'],
                [idType:'WORK_ORDER', externalId: 'workOrderId1']
        ]]
        Project project = new Project([projectId:'p1', name:"Project", externalId:'e1'])
        project.save()

        when:
        Map result = service.update(externalIds, project.projectId, false)

        then:
        result.status == "ok"

        when:
        Project project2 = Project.findByProjectId(project.projectId)

        then:
        project2.name == "Project"
        project2.externalId == "e1"
        project2.externalIds.size() == 3

        project2.getWorkOrderId() == "workOrderId1"
        project2.getInternalOrderId() == "internalOrderNumber1"
    }

    def "The project supports an externalIds embedded mapping when creating a project"() {
        setup:
        Map props = [name:"Project", externalId:'e1', externalIds:[
                [idType:'INTERNAL_ORDER_NUMBER', externalId: 'internalOrderNumber1'],
                [idType:'INTERNAL_ORDER_NUMBER', externalId: 'internalOrderNumber2'],
                [idType:'WORK_ORDER', externalId: 'workOrderId1']
        ]]

        when:
        Map result = service.create(props)

        then:
        result.status == "ok"

        when:
        Project project2 = Project.findByProjectId(result.projectId)

        then:
        project2.name == "Project"
        project2.externalId == "e1"
        project2.externalIds.size() == 3

        project2.getWorkOrderId() == "workOrderId1"
        project2.getInternalOrderId() == "internalOrderNumber1"
    }

    def "The project supports the geographicInfo embedded mapping when updating a project"() {
        setup:
        Map geographicInfo = [primaryElectorate:"Canberra", primaryState:"ACT", otherStates:["NSW"], otherElectorates:["Bean"]]

        Project project = new Project([projectId:'p1', name:"Project", externalId:'e1'])
        project.save()

        when:
        Map result = service.update([geographicInfo:geographicInfo], project.projectId, false)

        then:
        result.status == "ok"

        when:
        Project project2 = Project.findByProjectId(project.projectId)

        then:
        project2.name == "Project"
        project2.externalId == "e1"
        project2.geographicInfo.primaryElectorate == geographicInfo.primaryElectorate
        project2.geographicInfo.primaryState == geographicInfo.primaryState
        project2.geographicInfo.otherElectorates == geographicInfo.otherElectorates
        project2.geographicInfo.otherStates == geographicInfo.otherStates
    }

    def "The project supports the geographicInfo embedded mapping when creating a project"() {
        setup:
        Map geographicInfo = [primaryElectorate:"Canberra", primaryState:"ACT", otherStates:["NSW"], otherElectorates:["Bean"]]

        Map props = [name:"Project", externalId:'e1', geographicInfo: geographicInfo]

        when:
        Map result = service.create(props)

        then:
        result.status == "ok"

        when:
        Project project2 = Project.findByProjectId(result.projectId)

        then:
        project2.name == "Project"
        project2.externalId == "e1"
        project2.geographicInfo.primaryElectorate == geographicInfo.primaryElectorate
        project2.geographicInfo.primaryState == geographicInfo.primaryState
        project2.geographicInfo.otherElectorates == geographicInfo.otherElectorates
        project2.geographicInfo.otherStates == geographicInfo.otherStates
    }


    private Map buildRisksData() {
        List risks = [["consequence" : "Moderate",
                       "likelihood" : "Likely",
                       "residualRisk" : "Low",
                       "currentControl" : "programme control works to occur over a range of seasons throughout the year to minimise the risk of not being able to control invasive weeds",
                       "description" : "Seasonal Drought leading to inability to control weeds due to drought stress",
                       "threat" : "Seasonal conditions (eg. drought, flood, etc.)",
                       "riskRating" : "Significant"
                      ],[
                        "consequence" : "Major",
                        "likelihood" : "Possible",
                        "residualRisk" : "Medium",
                        "currentControl" : "review SWMS and undertake site risk assessment in accordance with Council policy",
                        "description" : "injury or death to staff or project partner",
                        "threat" : "Workplace health & safety (eg. Project staff and / or delivery partner injury or death)",
                        "riskRating" : "Significant"
                ]]
        [overallRisk:'High', dateUpdated:'2020-07-01T14:00:00Z', rows: risks]
    }


    void "Get brief"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1")
        project1.save(flush: true, failOnError: true)

        Project project2 = new Project(projectId: 'p2', name: "A project 2", status:  Status.DELETED)
        project2.save(flush: true, failOnError: true)

        def listOfIds = ['p1', 'p2']

        when:
        def response = service.getBrief(listOfIds)

        then:
        response != null
        response.size() == 1
        response[0].projectId == 'p1'
        response[0].name == 'A project 1'
    }

    void "Get brief - empty list"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1")
        project1.save(flush: true, failOnError: true)

        Project project2 = new Project(projectId: 'p2', name: "A project 2", status:  Status.DELETED)
        project2.save(flush: true, failOnError: true)

        def listOfIds = []

        when:
        def response = service.getBrief(listOfIds)

        then:
        response != null
        response.size() == 0
    }

    void "Get brief - with version"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1")
        project1.save(flush: true, failOnError: true)

        Project project2 = new Project(projectId: 'p2', name: "A project 2", status:  Status.DELETED)
        project2.save(flush: true, failOnError: true)

       def listOfIds = ['p1', 'p2']

        when:
        def response = service.getBrief(listOfIds, '1')

        then:
        response != null
    }

    void "Get by project id"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1")
        project1.save(flush: true, failOnError: true)

        when:
        def response = service.get('p1', [service.BASIC])

        then:
        response != null
        response.projectId == 'p1'
        response.name == 'A project 1'
    }

    void "Get by project id -  invalid id"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1")
        project1.save(flush: true, failOnError: true)

        when:
        def response = service.get('p2')

        then:
        response == null
    }

    void "Get project services"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1")
        project1.save(flush: true, failOnError: true)

        when:
        def response = service.getProjectServicesWithTargets('p1')
        def p = service.get('p1')

        then:
        1 * metadataService.getProjectServicesWithTargets(service.get('p1')) >> []
        response != null
    }

    void "Get project services -  invalid id"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1")
        project1.save(flush: true, failOnError: true)

        when:
        def response = service.getProjectServicesWithTargets('p2')

        then:
        response == null
    }

    void "Get by data resource id"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1')
        project1.save(flush: true, failOnError: true)

        when:
        def response = service.getByDataResourceId('1', 'active', [service.BASIC])

        then:
        response != null
        response.projectId == 'p1'
        response.name == 'A project 1'
    }

    void "Get by data resource id -  invalid id"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1')
        project1.save(flush: true, failOnError: true)

        when:
        def response = service.getByDataResourceId('2')

        then:
        response == null
    }

    void "list"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1', isCitizenScience: true)
        project1.save(flush: true, failOnError: true)
        Project project2 = new Project(projectId: 'p2', name: "A project 2", dataResourceId: '1', isCitizenScience: true, status: Status.DELETED)
        project2.save(flush: true, failOnError: true)

        when:
        def response = service.list([service.BASIC])

        then:
        response != null
        response.projectId == ['p1']
        response.name == ['A project 1']
    }

    void "list -  include deleted"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1', isCitizenScience: true)
        project1.save(flush: true, failOnError: true)
        Project project2 = new Project(projectId: 'p2', name: "A project 2", dataResourceId: '1', isCitizenScience: false, status: Status.DELETED)
        project2.save(flush: true, failOnError: true)

        when:
        def response = service.list([service.BASIC], true, false)

        then:
        response != null
        response.size() == 2
        response[0].projectId == 'p1'
        response[0].name == 'A project 1'
        response[1].projectId == 'p2'
        response[1].name == 'A project 2'
    }

    void "list citizen Science projects"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1', isCitizenScience: true)
        project1.save(flush: true, failOnError: true)
        Project project2 = new Project(projectId: 'p2', name: "A project 2", dataResourceId: '1', isCitizenScience: true, status: Status.DELETED)
        project2.save(flush: true, failOnError: true)

        when:
        def response = service.list([service.BASIC], false, true)

        then:
        response != null
        response.projectId == ['p1']
        response.name == ['A project 1']
    }

    void "list citizen Science projects -  include deleted"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1', isCitizenScience: true)
        project1.save(flush: true, failOnError: true)
        Project project2 = new Project(projectId: 'p2', name: "A project 2", dataResourceId: '1', isCitizenScience: true, status: Status.DELETED)
        project2.save(flush: true, failOnError: true)
        when:
        def response = service.list([service.BASIC], true, true)

        then:
        response != null
        response.size() == 2
        response[0].projectId == 'p1'
        response[0].name == 'A project 1'
        response[1].projectId == 'p2'
        response[1].name == 'A project 2'
    }

    void "list - empty"() {
        setup:
        when:
        def response = service.list([service.BASIC], true, true)

        then:
        response != null
        response.size() == 0
    }

    void "list merit projects"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1', isMERIT: true)
        project1.save(flush: true, failOnError: true)
        Project project2 = new Project(projectId: 'p2', name: "A project 2", dataResourceId: '1', isMERIT: true, status: Status.DELETED)
        project2.save(flush: true, failOnError: true)

        when:
        def response = service.listMeritProjects([service.BASIC], false)

        then:
        response != null
        response.projectId == ['p1']
        response.name == ['A project 1']
    }

    void "list merit projects -  include deleted"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1', isMERIT: true)
        project1.save(flush: true, failOnError: true)
        Project project2 = new Project(projectId: 'p2', name: "A project 2", dataResourceId: '1', isMERIT: true, status: Status.DELETED)
        project2.save(flush: true, failOnError: true)
        when:
        def response = service.listMeritProjects([service.BASIC], true)

        then:
        response != null
        response.size() == 2
        response[0].projectId == 'p1'
        response[0].name == 'A project 1'
        response[1].projectId == 'p2'
        response[1].name == 'A project 2'
    }

    void "list promoted"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1', promoteOnHomepage: 'yes')
        project1.save(flush: true, failOnError: true)
        Project project2 = new Project(projectId: 'p2', name: "A project 2", dataResourceId: '1', promoteOnHomepage: 'no')
        project2.save(flush: true, failOnError: true)

        when:
        def response = service.promoted()

        then:
        response != null
        response.projectId == ['p1']
        response.name == ['A project 1']
    }

    void "list projects for Ala harvesting"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1', alaHarvest: true)
        project1.save(flush: true, failOnError: true)
        Project project2 = new Project(projectId: 'p2', name: "A project 2", dataResourceId: '1', alaHarvest: false)
        project2.save(flush: true, failOnError: true)

        when:
        def response = service.listProjectForAlaHarvesting([max : 10, offset: 1, order: 'projectId', sort: 'desc'])

        then:
        response != null
        response.total == 1
    }

    void "list projects for Ala harvesting - empty"() {
        setup:

        when:
        def response = service.listProjectForAlaHarvesting([max : 10, offset: 1, order: 'projectId', sort: 'desc'])

        then:
        response != null
        response.total == 0
        response.list.size() == 0
    }

    void "load all"() {
        setup:
        def props = [[projectId: 'p1', name: "A project 1", dataResourceId: '1']]

        when:
        def response = service.loadAll(props)

        then:
        response != null
        response.size() == 1
        response[0].projectId == 'p1'
    }

    void "create - invalid"() {
        setup:
        Project project1 = new Project(projectId: 'p1', name: "A project 1", dataResourceId: '1', alaHarvest: true)
        project1.save(flush: true, failOnError: true)
        def props = [projectId: 'p1', name: "A project 1", dataResourceId: '1']

        when:
        def response = service.create(props)

        then:
        response != null
        response.status == 'error'
        response.error == 'Duplicate project id for create p1'
    }

    void "User have a role on an existing MERIT project"() {
        setup:
        Project project1 = new Project(projectId: '111', name: "Project 111", hubId:"12345").save()
        Project project2 = new Project(projectId: '222', name: "Project 222", hubId:"12345").save()
        Project project3 = new Project(projectId: '333', name: "Project 333").save()

        UserPermission up1 = new UserPermission(userId:'1', accessLevel:AccessLevel.admin, entityId:project1.projectId, entityType:Project.name, status: Status.ACTIVE).save()
        UserPermission up2 = new UserPermission(userId:'1', accessLevel:AccessLevel.caseManager, entityId:project2.projectId, entityType:Project.name, status: Status.ACTIVE).save()
        UserPermission up3 = new UserPermission(userId:'1', accessLevel:AccessLevel.admin, entityId:project3.projectId, entityType:Project.name, status: Status.ACTIVE).save()
        UserPermission up4 = new UserPermission(userId:'1', accessLevel:AccessLevel.readOnly, entityId:'12345', entityType:Hub.name, status: Status.ACTIVE).save()


        when:
        Boolean response = service.doesUserHaveHubProjects('1', '12345')

        then:
        response != null
        response == true

    }

    void "User have no role on an existing MERIT project"() {
        setup:
        Project project1 = new Project(projectId: '345', name: "Project 345", isMERIT: true, hubId:"12345")
        project1.save(flush: true, failOnError: true)
        UserPermission up = new UserPermission(userId:'2', accessLevel:AccessLevel.admin, entityId:'123', entityType:Project.name, status: Status.ACTIVE).save()


        when:
        Boolean response = service.doesUserHaveHubProjects('2', '12345')

        then:
        response != null
        response == false

    }

    void "The updateDataSet method will update (or insert) a data set into a Project"() {
        setup:
        Project project = new Project(projectId: '345', name: "Project 345", isMERIT: true, hubId:"12345")
        project.save(flush: true, failOnError: true)
        Map dataSet = [name: 'Test Data Set', description: 'Test Description', dataSetId:'d1']
        Project actual
        Project actual2
        Project actual3

        when:
        Map resp = service.updateDataSet(project.projectId, dataSet)
        Project.withNewSession {
            actual = Project.findByProjectId(project.projectId)
        }

        then:
        resp.status == 'ok'

        actual.projectId == project.projectId
        actual.name == project.name
        actual.isMERIT == project.isMERIT
        actual.hubId == project.hubId
        actual.custom.dataSets == [dataSet]

        when:
        Map dataSet2 = [name: 'Test Data Set 2', description: 'Test Description 2', dataSetId:'d2']
        resp = service.updateDataSet(project.projectId, dataSet2)
        Project.withNewSession {
            actual2 = Project.findByProjectId(project.projectId)
        }

        then:
        resp.status == 'ok'

        actual2.projectId == project.projectId
        actual2.name == project.name
        actual2.isMERIT == project.isMERIT
        actual2.hubId == project.hubId
        actual2.custom.dataSets == [dataSet, dataSet2]

        when:
        dataSet2.name = dataSet2.name + " - Updated"
        resp = service.updateDataSet(project.projectId, dataSet2)
        Project.withNewSession {
            actual3 = Project.findByProjectId(project.projectId)
        }

        then:
        resp.status == 'ok'

        actual3.projectId == project.projectId
        actual3.name == project.name
        actual3.isMERIT == project.isMERIT
        actual3.hubId == project.hubId
        actual3.custom.dataSets == [dataSet, dataSet2]
    }


    void "The deleteDataSet method will delete a dataSet from a Project"() {
        setup:
        Map dataSet = [name: 'Test Data Set', description: 'Test Description', dataSetId:'d1']
        Project project = new Project(projectId: '345', name: "Project 345", isMERIT: true, hubId:"12345", custom:[dataSets:[dataSet]])
        project.save(flush: true, failOnError: true)


        when:
        Map resp = service.deleteDataSet(project.projectId, 'd1')

        then:
        resp.status == 'ok'
        Project actual = Project.findByProjectId(project.projectId)
        actual.projectId == project.projectId
        actual.name == project.name
        actual.isMERIT == project.isMERIT
        actual.hubId == project.hubId
        actual.custom.dataSets == []

    }

    void "The update method merges the Project custom property"() {
        setup:
        Map dataSet = [name: 'Test Data Set', description: 'Test Description', dataSetId:'d1']
        Project project = new Project(projectId: '345', name: "Project 345", isMERIT: true, hubId:"12345", custom:[dataSets:[dataSet], details:[name:'name']])
        project.save(flush: true, failOnError: true)


        when:
        Map resp = service.update([custom:[details:[name:'name 2']]], project.projectId, false)

        then:
        resp.status == 'ok'
        Project actual = Project.findByProjectId(project.projectId)
        actual.projectId == project.projectId
        actual.name == project.name
        actual.isMERIT == project.isMERIT
        actual.hubId == project.hubId
        actual.custom.dataSets == project.custom.dataSets
        actual.custom.details == [name:'name 2']

    }

    void "The updateDataSet method is safe for concurrent access of different data sets"() {
        setup:
        Project project = new Project(projectId: 'p1', name: "Project 1", hubId:"12345")
        project.save(flush: true, failOnError: true)
        ExecutorService executor = Executors.newFixedThreadPool(20)
        Project project2

        when:
        List callables = []
        for (int i = 0; i < 100; i++) {
            Map dataSet = [name: 'Test Data Set', description: 'Test Description', dataSetId:'d' + i]
            Callable callable = new Callable() {
                @Override
                Object call() throws Exception {
                    service.updateDataSet(project.projectId, dataSet)
                    println "Updated data set ${dataSet.dataSetId}"
                    return null
                }
            }
            callables.add(callable)
        }
        executor.invokeAll(callables)
        Project.withNewSession {
            project2 = Project.findByProjectId(project.projectId)
        }

        then:
        project2.custom.dataSets.size() == 100
        for (int i = 0; i < 100; i++) {
            project2.custom.dataSets.find { it.dataSetId == 'd' + i } != null
        }

    }

    void "getAllMERITProjectIds should only get MERIT projects"() {
        setup:
        Project project1 = new Project(projectId: '111', name: "Project 111", hubId:"12345", isMERIT: true).save()
        Project project2 = new Project(projectId: '222', name: "Project 222", hubId:"12345", isMERIT: true).save()
        Project project3 = new Project(projectId: '333', name: "Project 333", isMERIT: false).save()

        when:
        def results = service.getAllMERITProjectIds()

        then:
        results.size() == 2
        results.contains('111')
        results.contains('222')
    }

    void "orderLayerIntersectionsByAreaOfProjectSites should sum proportions order intersections by descending order"() {
        setup:
        Project project1 = new Project(projectId: '111', name: "Project 111", hubId:"12345", isMERIT: true).save()
        Site site1 = new Site(siteId: 's1', name: "Site 1", type: "compound", projects: ['111'], extent: [ source: "point", geometry: [intersectionAreaByFacets: ["cl11163": ["bean": 0.1, "canberra": 0.2, "fenner": 0.25]]]]).save()
        Site site2 = new Site(siteId: 's2', name: "Site 2", type: "compound", projects: ['111'], extent: [ source: "point", geometry: [intersectionAreaByFacets: ["cl11163": ["bean": 0.7, "canberra": 0.4, "fenner": 0.5]]]]).save()
        project1.metaClass.getDbo = { new BasicDBObject(project1.properties) }
        Map projectMap
        projectMap = service.toMap(project1, 'all')

        when:
        Map result = service.orderLayerIntersectionsByAreaOfProjectSites(projectMap)

        then:
        result.size() == 1
        result."cl11163"[0] == "bean"
        result."cl11163"[1] == "fenner"
        result."cl11163"[2] == "canberra"
    }


    void "getRepresentativeSitesOfProject should get EMSA site or Reporting sites only" () {
        setup:
        ManagementUnit mu = new ManagementUnit(managementUnitId: 'mu1', name: "Management Unit 1", managementUnitSiteId: 's4').save()
        Project project1 = new Project(projectId: '111', name: "Project 111", hubId:"12345", isMERIT: true, managementUnitId: 'mu1')
        project1.save()
        Site site1 = new Site(siteId: 's1', name: "Site 1", type: "compound", projects: ['111'], extent: [ source: "point", geometry: [intersectionAreaByFacets: ["cl11163": ["bean": 0.1, "canberra": 0.2, "fenner": 0.25]]]]).save()
        Site site2 = new Site(siteId: 's2', name: "Site 2", type: "compound", projects: ['111'], extent: [ source: "point", geometry: [intersectionAreaByFacets: ["cl11163": ["bean": 0.7, "canberra": 0.4, "fenner": 0.5]]]]).save()
        Site site3 = new Site(siteId: 's3', name: "Site 3", externalIds: [[idType: ExternalId.IdType.MONITOR_PROTOCOL_INTERNAL_ID, externalId: '1']], projects: ['111'], extent: [ source: "point", geometry: [intersectionAreaByFacets: ["cl11163": ["bean": 0.0, "canberra": 0.1, "fenner": 0.6]]]]).save()
        Site site4 = new Site(siteId: 's4', name: "Site 4", type: "worksArea", extent: [ source: "point", geometry: [intersectionAreaByFacets: ["cl11163": ["bean": 0.7, "canberra": 0.4, "fenner": 0.5]]]]).save()
        Site site5 = new Site(siteId: 's5', name: "Site 5", type: "worksArea", projects: ['111'], extent: [ source: "point", geometry: [intersectionAreaByFacets: ["cl11163": ["bean": 0.7, "canberra": 0.4, "fenner": 0.5]]]]).save()
        project1.metaClass.getDbo = { new BasicDBObject(project1.properties) }
        Map projectMap
        projectMap = service.toMap(project1, ProjectService.ALL)

        when: // returns reporting and EMSA sites Only
        List result = service.getRepresentativeSitesOfProject(projectMap)

        then:
        result.size() == 3
        result.siteId[0] == 's1'
        result.siteId[1] == 's2'
        result.siteId[2] == 's3'

        when: // returns planning/project extent sites
        site1.type = Site.TYPE_PROJECT_AREA
        site1.save()
        site2.type = Site.TYPE_WORKS_AREA
        site2.save()
        site3.delete()
        projectMap = service.toMap(project1, ProjectService.ALL)
        result = service.getRepresentativeSitesOfProject(projectMap)

        then:
        result.size() == 3
        result.siteId[0] == 's1'
        result.siteId[1] =='s2'
        result.siteId[2] == 's5'

        when: // returns Management Unit boundaries
        site1.projects = site2.projects = site5.projects = []
        site1.save()
        site2.save()
        site5.save()
        projectMap = service.toMap(project1, ProjectService.ALL)
        result = service.getRepresentativeSitesOfProject(projectMap)

        then:
        result.size() == 1
        result.siteId[0] == 's4'

        when:// returns empty
        project1.managementUnitId = null
        project1.save()
        projectMap = service.toMap(project1, ProjectService.ALL)
        result = service.getRepresentativeSitesOfProject(projectMap)

        then:
        result.isEmpty()
    }

}
