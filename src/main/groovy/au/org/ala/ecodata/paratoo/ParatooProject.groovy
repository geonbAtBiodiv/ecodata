package au.org.ala.ecodata.paratoo

import au.org.ala.ecodata.AccessLevel
import au.org.ala.ecodata.ActivityForm
import au.org.ala.ecodata.Project
import au.org.ala.ecodata.Service
import au.org.ala.ecodata.Site

/** DTO for a response to the paratoo app */
class ParatooProject {

    String id
    String name
    AccessLevel accessLevel
    Project project
    List<ActivityForm> protocols
    Map projectArea = null
    List<Site> plots = null

    List<Map> getDataSets() {
        project?.custom?.dataSets
    }

    List<Service> findProjectServices() {
        project.findProjectServices()
    }

    List<String> getMonitoringProtocolCategories() {
        project.getMonitoringProtocolCategories()
    }
}
