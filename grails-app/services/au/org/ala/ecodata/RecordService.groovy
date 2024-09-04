package au.org.ala.ecodata

import au.com.bytecode.opencsv.CSVWriter
import au.org.ala.web.AuthService
import grails.converters.JSON
import grails.util.Holders
import groovy.json.JsonSlurper
import org.apache.commons.io.FileUtils
import org.apache.commons.lang.StringEscapeUtils
import org.apache.commons.lang.time.DateUtils
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.mime.HttpMultipartMode
import org.apache.http.entity.mime.MultipartEntity
import org.apache.http.entity.mime.content.FileBody
import org.apache.http.entity.mime.content.StringBody
import org.apache.http.impl.client.DefaultHttpClient
import org.joda.time.DateTime
import org.joda.time.DateTimeZone
import org.joda.time.format.DateTimeFormatter
import org.joda.time.format.ISODateTimeFormat

import static au.org.ala.ecodata.Status.ACTIVE
import static au.org.ala.ecodata.Status.DELETED
import static grails.async.Promises.task

/**
 * Services for handling the creation of records with images.
 */
class RecordService {
    private static final Object LOCK_1 = new Object() {};
    static transactional = false

    def grailsApplication
    ActivityService activityService
    MetadataService metadataService
    OutputService outputService
    ProjectService projectService
    SiteService siteService
    UserService userService
    RecordAlertService recordAlertService
    SensitiveSpeciesService sensitiveSpeciesService
    DocumentService documentService
    CommonService commonService
    AuthService authService

    final def ignores = ["action", "controller", "associatedMedia"]
    private static final List<String> EXCLUDED_RECORD_PROPERTIES = ["_id", "activityId", "dateCreated", "json", "outputId", "projectActivityId", "projectId", "status", "dataResourceUid"]
    static final String COMMON_NAME = 'COMMONNAME'
    static final String SCIENTIFIC_NAME = 'SCIENTIFICNAME'
    static final String COMMON_NAME_SCIENTIFIC_NAME = 'COMMONNAME(SCIENTIFICNAME)'
    static final String SCIENTIFIC_NAME_COMMON_NAME = 'SCIENTIFICNAME(COMMONNAME)'

    def getProjectActivityService() {
        grailsApplication.mainContext.projectActivityService
    }

    def getAll(int max, int offset) {
        def list = Record.createCriteria().list(max: max, offset: offset) {
            eq("status", ACTIVE)
        }

        [count: list.totalCount, list: list.collect { toMap(it) }]
    }

    def countRecords() {
        Record.countByStatus(ACTIVE)
    }

    def exportRecordsToCSV(OutputStream outputStream, String projectId, String userId, List<String> restrictedProjectActivities) {
        // Different Records may have different DwC attributes, as these are based on the 'dwcAttribute' mapping in the
        // Output Metadata, so first we need to determine the full set of unique property names for all records...
        Set<String> properties = []

        def attributeCollection = Record.collection.mapReduce("function map() {" +
                "    for (var key in this) { emit(key, null); }" +
                "  }",
                "function reduce(key, stuff) { return null; }",
                "attributeCollection", [:])

        properties.addAll(attributeCollection.results().findAll().collect { it._id })
        attributeCollection.drop()

        // ...then we can exclude any properties that we do not want in the CSV
        properties.removeAll(EXCLUDED_RECORD_PROPERTIES)

        CSVWriter csvWriter = new CSVWriter(new OutputStreamWriter(outputStream))
        csvWriter.writeNext(properties as String[])

        List<Record> recordList = Record.withCriteria {
            if (projectId) {
                eq "projectId", projectId
            }
            ne "status", DELETED

            // exclude records that do not have lat/lng coords
            isNotNull "decimalLatitude"
            isNotNull "decimalLongitude"

            or {
                eq "userId", userId
                not { 'in' "projectActivityId", restrictedProjectActivities }
            }
        }

        log.info("Number of records to export: ${recordList.size()}")

        // write out each record
        recordList.each {
            Map map = toMap(it)
            String[] row = properties.collect {
                if (it == "multimedia") {
                    map.multimedia?.collect { it.identifier }?.join(";")
                } else if (it == "lastUpdated") {
                    map.lastUpdated?.format("dd-MM-yyyy")
                } else {
                    map[it]
                }
            }
            csvWriter.writeNext(row)
        }

        csvWriter.flush()
        csvWriter.close()
    }

    /**
     * Export records to CSV for a project. This implementation is unlikely to scale beyond 50k
     * records.
     */
    private exportRecordBasedProject(CSVWriter csvWriter, String projectId, String userId, List<String> restrictedProjectActivities) {
        List<Record> recordList = Record.withCriteria {
            eq "projectId", projectId
            ne "status", DELETED

            or {
                eq "userId", userId
                not { 'in' "projectActivityId", restrictedProjectActivities }
            }
        }

        log.info("Number of records to export: ${recordList.size()}")

        //write out each record
        recordList.each {
            Map map = toMap(it)
            csvWriter.writeNext([
                    map.occurrenceID ?: "",
                    map.scientificName ?: "",
                    map.family ?: "",
                    map.kingdom ?: "",
                    map.decimalLatitude ?: "",
                    map.decimalLongitude ?: "",
                    map.eventDate ?: "",
                    map.userId ?: "",
                    map.recordedBy ?: "",
                    map.usingReverseGeocodedLocality ?: "",
                    map.individualCount ?: "",
                    map.submissionMethod ?: "",
                    map.georeferenceProtocol ?: "",
                    map.identificationVerificationStatus ?: "",
                    map.occurrenceRemarks ?: "",
                    map.coordinateUncertaintyInMeters ?: "",
                    map.geodeticDatum ?: "",
                    map.imageLicence ?: "",
                    map.locality ?: "",
                    map.multimedia ? map.multimedia.collect { it.identifier }.join(";") : "",
                    it.lastUpdated ? it.lastUpdated.format("dd-MM-yyyy") : ""
            ] as String[])
        }
        csvWriter.flush()
    }

    /**
     * Updates record status by output id
     *
     * @param id output id
     * @params status record status
     * @return list of errors.
     */
    List updateRecordStatusByOutput(String id, String status = Status.ACTIVE) {
        List<Record> records = Record.findAllByOutputId(id)
        List<String> errors

        records?.each { record ->
            record.status = status
            try {
                record.save(flush: true)
            }
            catch (Exception e) {
                Record.withSession { session -> session.clear() }
                def error = "Error updating record ${record.occurrenceID} - ${e.message}"
                log.error error, e
                errors << [status: 'error', error: error]
            }
        }

        errors
    }

    /**
     * Create a record based on the supplied JSON
     *
     * @param json
     * @return
     */
    def createRecord(json, boolean doNotAlert = false) {
        Record record = new Record().save(true)
        updateRecord(record, json, [:], doNotAlert)
        record
    }

    def getAllByActivity(String activityId, String projectId = null, version = null) {
        if (version) {
            def all = AuditMessage.findAllByProjectIdAndEntityTypeAndDateLessThanEquals(projectId, Record.class.name,
                    new Date(version as Long), [sort: 'date', order: 'desc'])
            def records = []
            def found = []
            all?.each {
                if (it.entity.activityId == activityId && !found.contains(it.entity.projectActivityId)) {
                    if (it.entityType == AuditEventType.Insert || it.entityType == AuditEventType.Update) {
                        records << it.entity
                    }
                    found << it.entity.projectActivityId
                }
            }

            records
        } else {
            Record.findAllByActivityIdAndStatus(activityId, ACTIVE).collect { toMap(it) }
        }
    }

    def getAllByProjectActivity(String projectActivityId, version = null) {
        if (version) {
            def recordIds = Record.findAllByProjectActivityId(projectActivityId).collect {
                it.id
            }
            def all = AuditMessage.findAllByEntityIdInListAndEntityTypeAndDateLessThanEquals(recordIds, Record.class.name,
                    new Date(version as Long), [sort: 'date', order: 'desc'])
            def records = []
            def found = []
            all?.each {
                if (!found.contains(it.entityId)) {
                    found << it.entityId
                    if (it.entity.status == ACTIVE &&
                            (it.eventType == AuditEventType.Insert || it.eventType == AuditEventType.Update)) {
                        records << it.entity
                    }
                }
            }

            records
        } else {
            Record.findAllByProjectActivityIdAndStatus(projectActivityId, ACTIVE).collect { toMap(it) }
        }
    }

    def getAllByProject(String projectId) {
        Record.findAllByProjectIdAndStatus(projectId, ACTIVE).collect { toMap(it) }
    }

    def getAllRecordsByActivityList(List<String> activityList) {
        Record.findAllByActivityIdInList(activityList).collect { toMap(it) }
    }

    /**
     * Create a record with the supplied map of fileName -> byte[].
     *
     * @param json
     * @param fileMap
     */
    def createRecordWithImages(json, fileMap, boolean doNotAlert = false) {
        Record record = new Record().save(true)
        def errors = updateRecord(record, json, fileMap, doNotAlert)
        [record, errors]
    }

    /**
     * Update guid for the given record id
     *
     * @param id record id or occurence id
     * @param guid species unique identifier.
     */
    Map updateGuid(id, String guid) {
        Map result

        Record record = Record.findByOccurrenceID(id)
        if (record) {
            try {
                def props = [guid: guid]
                commonService.updateProperties(record, props)

                result = [status: 'ok', id: record.occurrenceID]
            } catch (Exception e) {
                Record.withSession { session -> session.clear() }
                def error = "Error updating record ${id} - ${e.message}"
                log.error error, e
                result = [status: 'error', error: error]
            }
        } else {
            def error = "Error updating record - no such id ${id}"
            log.error error
            result = [status: 'error', error: error]
        }

        result
    }

    /**
     * Update the supplied record including updates to any supplied images.
     * This method will take imageMetadata references in the json in the multimedia section
     * or will upload images supplied in the imageMap which has contains
     * filename -> byte[]
     *
     * @param record The Record to be updated
     * @param json A map or JSONObject containing the record data. This data must contain a userId.
     * @param imageMap a map of image resources to be associated with the record
     *
     * @throws Exception in case of a validation failure or any unexpected system exception
     */
    private void updateRecord(Record record, json, Map imageMap = [:], boolean doNotAlert = false) {

        def userDetails = userService.getCurrentUserDetails()
        // Always ownership of record to user id in the properties. It is now possible for Administrators to regenerate records for the whole project.
        // This prevents ownership being assigned to them.
        if (json.userId) {
            userDetails = authService.getUserForUserId(json.userId)
        }

        if (!userDetails) {
            throw new Exception("Unable to lookup user with ID: ${json.userId}. Check authorised systems in auth.")
        }
        record.userId = userDetails.userId
        record.recordedBy = userDetails.displayName

        //set all supplied properties
        json.each {
            if (it.key in ["decimalLatitude", "decimalLongitude"] && it.value) {
                record[it.key] = it.value.toString().toDouble()
            } else if (it.key in ["coordinateUncertaintyInMeters", "individualCount"] && it.value) {
                record[it.key] = it.value.toString().toInteger()
            } else if (it.key in ["eventDate"] && it.value) {
                String parsedDate = toStringIsoDateTime(it.value)
                if (parsedDate) {
                    record[it.key] = parsedDate
                }
            } else if (it.key in ["dateCreated", "lastUpdated"] && it.value) {
                //do nothing we these values...
            } else if (!ignores.contains(it.key) && it.value) {
                record[it.key] = it.value
            }
        }

        // Apply sensitive coordinates
        def activity = getProjectActivityService().get(record?.projectActivityId)
        String name = getSpeciesName(record, activity)
        if (record.decimalLatitude && record.decimalLongitude && name) {
            Map sensitive = sensitiveSpeciesService.findSpecies(name.trim(), record.decimalLatitude, record.decimalLongitude)
            if (sensitive?.lat && sensitive?.lng) {
                record.generalizedDecimalLatitude = sensitive.lat
                record.generalizedDecimalLongitude = sensitive.lng
            }
        }

        //if no projectId is supplied, use default
        if (!record.projectId) {
            record.projectId = grailsApplication.config.getProperty('records.default.projectId')
        }

        //use the data resource UID associated with the project
        def project = Project.findByProjectId(record.projectId)
        record.dataResourceUid = project.dataResourceId

        //clear current imageMetadata references on the record
        record.multimedia = []

        //persist any supplied images into imageMetadata service
        if (json.multimedia) {
            try {
                json.multimedia.eachWithIndex { image, idx ->

                    record.multimedia[idx] = [:]

                    // Each image in Ecodata may have an associated Document entity. We need to maintain this relationship in the resulting Record entity
                    record.multimedia[idx].documentId = image.documentId

                    // reconcile new with old images...
                    // Only upload images that are NOT already in images.ala.org.au
                    if (!image.creator) {
                        image.creator = userDetails.displayName
                    }

                    if (!image.rightsHolder) {
                        image.rightsHolder = userDetails.displayName
                    }

                    def alreadyLoaded = false

                    def document = documentService.get(image.documentId)

                    // Rely on document to check whether image has been uploaded to image server. Output data will not have imageId.
                    if (!document.imageId) {
                        log.debug "Uploading imageMetadata - ${image.identifier}"
                        File downloadedFile
                        boolean toDelete = false
                        if (document.filepath && document.filename) {
                            downloadedFile = new File(documentService.fullPath(document.filepath, document.filename))
                        }

                        if (!downloadedFile.exists() && image.identifier) {
                            downloadedFile = download(record.occurrenceID, idx, image.identifier)
                            toDelete = true
                        }

                        if(downloadedFile) {
                            def imageId = uploadImage(record, downloadedFile, image)
                            if (imageId) {
                                // successfully uploaded image to server
                                record.multimedia[idx].imageId = imageId
                                record.multimedia[idx].identifier = getImageUrl(imageId)
                                document.imageId = imageId
                                documentService.update(document, document.documentId)
                            }
                            else {
                                // use document
                                record.multimedia[idx].identifier = document.url
                            }

                            if (toDelete) {
                                downloadedFile.delete()
                            }
                        }
                    } else {
                        alreadyLoaded = true
                        //re-use the existing imageId rather than upload again
                        log.debug "Image already uploaded - ${document.imageId}"
                        record.multimedia[idx].imageId = document.imageId
                        record.multimedia[idx].identifier = getImageUrl(document.imageId)
                        if (record.multimedia[idx].identifier != document.identifier) {
                            documentService.update([identifier: record.multimedia[idx].identifier], document.documentId)
                        }
                    }

                    setDCTerms(image, record.multimedia[idx])

                    if (alreadyLoaded) {
                        log.debug "Refreshing metadata - ${image.identifier}"
                        //refresh metadata in imageMetadata service
                        updateImageMetadata(image.imageId, record, record.multimedia[idx])
                    }
                }
            } catch (Exception ex) {
                log.error("Error uploading image to ${grailsApplication.config.getProperty('imagesService.baseURL')} -${ex.message}")
            }

        } else if (imageMap) {
            //upload the images supplied as bytes
            def idx = 0
            imageMap.each { imageFileName, imageInBytes ->
                def metadata = [
                        title  : imageFileName,
                        creator: userDetails.displayName
                ]
                def imageId = uploadImageInByteArray(record, imageFileName, imageInBytes, metadata)
                record.multimedia[idx] = [:]
                record.multimedia[idx].imageId = imageId
                record.multimedia[idx].identifier = getImageUrl(imageId)
                //we only support one set of metadata for all images for this method
                setDCTerms(json, record.multimedia[idx])
                idx++
            }
        }
        record.save(flush: true)
        // we do not want to alert users every time admin regenerates records
        !doNotAlert && recordAlertService.alertSubscribers(record)
    }

    String toStringIsoDateTime(def date) {

        if (date instanceof Date) {
            return new DateTime(date, DateTimeZone.UTC).toDateTimeISO().toString()
        } else {
            String dateString = date.toString()

            try {
                DateTimeFormatter parser = ISODateTimeFormat.dateOptionalTimeParser()
                parser.parseDateTime(dateString)
                // No exceptions, the string is an ISO date
                return dateString

            } catch (IllegalArgumentException e) {
                // input parameter is not parsable to an iso Date with optional time, let's ignore it
                return null
            }
        }
    }

    private setDCTerms(image, multimediaElement) {
        multimediaElement.license = image.license
        multimediaElement.rights = image.rights
        multimediaElement.rightsHolder = image.rightsHolder
        multimediaElement.title = image.title
        multimediaElement.type = image.type
        multimediaElement.format = image.format
        multimediaElement.creator = image.creator
    }

    private def getImageUrl(imageId) {
        grailsApplication.config.getProperty('imagesService.baseURL') + "/image/proxyImageThumbnailLarge?imageId=" + imageId
    }

    /**
     * Add the supplied imageMetadata in bytes to the supplied record.
     *
     * @param record
     * @param originalName
     * @param imageAsBytes
     */
    private def uploadImageInByteArray(Record record, String originalName, byte[] imageAsBytes, Map metadata) {

        //write bytes to temp file
        def fileToUpload = File.createTempFile("multipart-upload-" + System.currentTimeMillis(), ".tmp")
        fileToUpload.withOutputStream {
            it.write imageAsBytes
        }

        //upload
        def imageId = uploadImage(record, fileToUpload, metadata)

        if (!record.multimedia) {
            record.multimedia = []
        }

        //remove temp file
        fileToUpload.delete()

        //return imageMetadata Id
        imageId
    }


    def listByProjectId(Map params, Date lastUpdated, List restrictedProjectActivities = []) {
        def list = Record.createCriteria().list(max: params.max, offset: params.offset) {
            and {
                if (lastUpdated) {
                    'gt'('lastUpdated', lastUpdated)
                }
                eq "projectId", params.projectId
                eq "status", params.status
                not { 'in' "projectActivityId", restrictedProjectActivities }
            }
            order(params.sort, params.order)
        }

        [total: list?.totalCount, list: list?.collect { toMap(it) }]
    }

    def list(Map params) {
        def list = Record.createCriteria().list(max: params.max, offset: params.offset) {
            params.query?.each { prop, value ->

                if (value instanceof List) {
                    inList(prop, value)
                } else {
                    eq(prop, value)
                }
            }
            order(params.sort, params.order)
        }

        [total: list?.totalCount, list: list?.collect { toMap(it) }]
    }

    /**
     * Update the metadata for an imageMetadata in the imageMetadata service.
     * This will include updates to tags and licensing.
     *
     * @param imageId
     * @param record
     * @param metadataProperties
     * @return
     */
    private def updateImageMetadata(String imageId, record, metadataProperties) {

        log.info("Updating imageMetadata metadata for imageMetadata: ${imageId} from record ${record.occurrenceID}")

        //upload an image metadata
        def entity = new MultipartEntity(HttpMultipartMode.BROWSER_COMPATIBLE)
        entity.addPart("metadata", new StringBody(([
                "title"       : metadataProperties.title,
                "creator"     : metadataProperties.creator,
                "rights"      : metadataProperties.rights,
                "rightsHolder": metadataProperties.rightsHolder ? metadataProperties.rightsHolder : metadataProperties.creator,
                "license"     : metadataProperties.license
        ] as JSON).toString()))

        if (record.tags) {
            entity.addPart("tags", new StringBody((record.tags as JSON).toString()))
        }

        def httpClient = new DefaultHttpClient()
        def httpPost = new HttpPost(grailsApplication.config.getProperty('imagesService.baseURL') + "/ws/updateMetadata/${imageId}")
        httpPost.setHeader("X-ALA-userId", "${record.userId}");
        httpPost.setHeader('apiKey', "${grailsApplication.config.getProperty('api_key')}");
        httpPost.setEntity(entity)
        def response = httpClient.execute(httpPost)
        def result = response.getStatusLine()
    }

    /**
     * Upload the supplied imageMetadata to the imageMetadata service.
     *
     * @param record
     * @param fileToUpload
     * @param imageMetadata
     * @return
     */
    private def uploadImage(Record record, File fileToUpload, imageMetadata) {

        //upload an imageMetadata
        def entity = new MultipartEntity(HttpMultipartMode.BROWSER_COMPATIBLE)
        if (!fileToUpload.exists()) {
            log.error("File to upload does not exist or can not be read. " + fileToUpload.getAbsolutePath())
        } else {
            log.debug("File to upload: " + fileToUpload.getAbsolutePath() + ", size:" + fileToUpload.length())
        }
        def fileBody = new FileBody(fileToUpload, "image/jpeg")
        log.debug "imageMetadata upload: ${imageMetadata}"
        entity.addPart("image", fileBody)
        entity.addPart("metadata", new StringBody(([
                "occurrenceId"    : record.occurrenceID,
                "projectId"       : record.projectId,
                "dataResourceUid" : record.dataResourceUid,
                "originalFilename": imageMetadata.title,
                "title"           : imageMetadata.title,
                "creator"         : imageMetadata.creator,
                "rights"          : imageMetadata.rights,
                "rightsHolder"    : imageMetadata.rightsHolder ? imageMetadata.rightsHolder : imageMetadata.creator,
                "license"         : imageMetadata.license,
                "dateTaken"       : imageMetadata?.created,
                "systemSupplier"  : grailsApplication.config.getProperty('imageSystemSupplier') ?: "ecodata"
        ] as JSON).toString()))

        if (record.tags) {
            entity.addPart("tags", new StringBody((record.tags as JSON).toString()))
        }

        def httpClient = new DefaultHttpClient()
        def httpPost = new HttpPost(grailsApplication.config.getProperty('imagesService.baseURL') + "/ws/uploadImage")
        httpPost.setHeader("X-ALA-userId", "${record.userId}");
        httpPost.setHeader('apiKey', "${grailsApplication.config.getProperty('api_key')}");
        httpPost.setEntity(entity)
        def response = httpClient.execute(httpPost)
        def result = response.getStatusLine()
        def responseBody = response.getEntity().getContent().getText()
        log.debug("Image service response code: " + result.getStatusCode())
        def jsonSlurper = new JsonSlurper()
        def map = jsonSlurper.parseText(responseBody)
        log.debug("Image ID: " + map["imageId"])
        if (!map["imageId"]) {
            log.error("Problem uploading images. Response: " + map)
        }
        map["imageId"]
    }

    private File download(recordId, idx, address) {
        def directory = grailsApplication.config.getProperty('temp.dir') + File.separator + "record" + File.separator + recordId
        File mediaDir = new File(directory)
        if (!mediaDir.exists()) {
            FileUtils.forceMkdir(mediaDir)
        }
        def destFile = new File(directory + File.separator + idx + "_" + address.tokenize("/")[-1])
        def out = new BufferedOutputStream(new FileOutputStream(destFile))
        log.debug("Trying to download..." + address)
        String decodedAddress = StringEscapeUtils.unescapeXml(address)
        log.debug("Decoded address " + decodedAddress)
        out << new URL(decodedAddress).openStream()
        out.close()
        destFile
    }

    /**
     * Get record for a given activityId
     */
    def getForActivity(String activityId) {
        Record.findAllByActivityIdAndStatus(activityId, Status.ACTIVE).collect { toMap(it) }
    }

    /**
     * Get record for a given activityId
     */
    def getRecordForOutputSpeciesId(String outputSpeciesId) {
        def record = Record.findByOutputSpeciesIdAndStatus(outputSpeciesId, Status.ACTIVE)
        record ? toMap(record) : [:]
    }

    def toMap(record) {
        def mapOfProperties = GormMongoUtil.extractDboProperties(record.getProperty("dbo"))
        //def mapOfProperties = dbo.toMap()
        mapOfProperties.recordNumber = record.getRecordNumber(grailsApplication.config.getProperty('biocollect.activity.sightingsUrl')) //record.recordNumber
        mapOfProperties.remove("_id")
        mapOfProperties
    }

    /**
     * Export project sightings to CSV.
     */
    def exportCSVProject(OutputStream outputStream, String projectId, String modelName, String userId, List<String> restrictedProjectActivities) {
        CSVWriter csvWriter = new CSVWriter(new OutputStreamWriter(outputStream))
        csvWriter.writeNext(
                [
                        "occurrenceID",
                        "scientificName",
                        "family",
                        "kingdom",
                        "decimalLatitude",
                        "decimalLongitude",
                        "eventDate",
                        "userId",
                        "recordedBy",
                        "usingReverseGeocodedLocality",
                        "individualCount",
                        "submissionMethod",
                        "georeferenceProtocol",
                        "identificationVerificationStatus",
                        "occurrenceRemarks",
                        "coordinateUncertaintyInMeters",
                        "geodeticDatum",
                        "imageLicence",
                        "locality",
                        "associatedMedia",
                        "modified",
                        "locationID"
                ] as String[]
        )

        List<Map> projects
        if (projectId) {
            projects = [projectService.get(projectId, projectService.FLAT)]
        } else {
            projects = projectService.search([:], projectService.FLAT)
        }

        projects.each { Map project ->
            exportActivityBasedProject(csvWriter, project, modelName)
            exportRecordBasedProject(csvWriter, project.projectId, userId, restrictedProjectActivities)
        }

        csvWriter.flush()
        csvWriter.close()
    }

    /**
     * Export activities to CSV of darwin core terms.
     *
     * @param csvWriter
     * @param project
     * @param modelName
     */
    private def exportActivityBasedProject(csvWriter, project, modelName) {

        def modelsMap = [:]
        def projectSite = siteService.get(project.projectSiteId)
        def today = (new Date()).format("dd-MM-yyyy")
        def projectDates = mapDates(today, project.plannedStartDate, project.plannedEndDate, project.actualStartDate, project.actualEndDate)

        //export activity based data
        for (def activity in activityService.findAllForProjectId(project.projectId, activityService.FLAT)) {
            def site, activityDWC = [:]

            // map collector to activity record
            if (activity.collector) activityDWC.userId = activity.collector

            // map site info to activity record
            if (activity.siteId) site = siteService.get(activity.siteId)
            if (!site) site = projectSite
            if (site) mapSiteToDWC(activityDWC, site)

            // map date info to activity record
            activityDWC.eventDate = mapDates(today, activity.plannedStartDate, activity.plannedEndDate, activity.startDate, activity.endDate)
            if (!activityDWC.eventDate) activityDWC.eventDate = projectDates

            // map each output to a record
            def outputs
            if (modelName)
                outputs = outputService.findAllForActivityIdAndName(activity.activityId, modelName)
            else
                outputs = outputService.findAllForActivityId(activity.activityId)
            for (def output in outputs) {
                def model = modelsMap[output.name]
                if (!model) model = modelsMap[output.name] = metadataService.getOutputDataModelByName(output.name)
                if (!model || !model.darwinCore) continue
                def dwc = activityDWC.clone()
                if (output.dateCreated) dwc.eventDate = output.dateCreated.format("dd-MM-yyyy")
                exportOutputTree(csvWriter, dwc, output.data, model.dataModel)
            }
        }
    }

    private def mapSiteToDWC(dwc, site) {
        def extent = site.extent, geom = extent?.geometry
        if (!geom) return // can't do much with this site
        if (extent.source == "pid" && geom.centre?.size() != 2 && site.poi?.size() > 0)
            geom = site.poi[0].geometry
        if (geom.locality) dwc.locality = geom.locality
        if (geom.uncertainty) dwc.coordinateUncertaintyInMeters = geom.uncertainty
        if (site.siteId) dwc.locationID = site.siteId
        def centre = geom.centre
        if (centre && centre.size() == 2) {
            dwc.decimalLatitude = centre[1]
            dwc.decimalLongitude = centre[0]
        }
    }

    private def mapDates(today, plannedStart, plannedEnd, actualStart, actualEnd) {
        def dStart = actualStart ?: plannedStart
        def dEnd = actualEnd ?: plannedEnd
        if (dStart && dEnd) return dStart.format("dd-MM-yyyy") + ' ' + dEnd.format("dd-MM-yyyy")
        if (dStart) return dStart.format("dd-MM-yyyy") + ' ' + today
        return null
    }

    /**
     * DarwinCore export mappings for project sightings (outputs)
     * (in order of increasing overwrite preference)
     *
     * Project:
     *     site(projectSiteId) {*       siteId -> locationId
     *       extent.geometry or poi[0].geometry {*         locality -> locality
     *         uncertainty -> coordinateUncertaintyInMeters
     *         centre[0] -> decimalLongitude
     *         centre[1] -> decimalLatitude
     *}*}*     plannedStartDate/actualStartDate plannedEndDate/actualEndDate/today -> eventDate
     *
     * Activity:
     *     site(siteId) -> [overwrite mappings from project site]
     *     plannedStartDate/startDate plannedEndDate/endDate/today -> eventDate
     *     collector -> userId
     *
     * Output: only for model marked "darwinCore: true"
     *     dateCreated -> eventDate
     *     assessmentDate -> eventDate
     *     lastUpdated -> modified
     *     collector -> recordedBy
     *     assessor -> recordedBy
     *     eventNotes -> occurrenceRemarks
     *     notes -> occurrenceRemarks
     *     (dataType:species).name -> scientificName
     *     fields marked "darwinCore: <dwcName>" -> dwcName
     *
     * Output sublist marked "darwinCore: true"
     *     recursive generation of records
     */
    private def exportOutputTree(csvWriter, dwc, output, model) {
        // map leaf-level fields to darwin core
        if (output.assessmentDate) dwc.eventDate = output.assessmentDate.format("dd-MM-yyyy")
        if (output.lastUpdated) dwc.modified = output.lastUpdated.format("dd-MM-yyyy")
        if (output.locality) dwc.locality = output.locality
        if (output.assessor)
            dwc.recordedBy = output.assessor
        else if (output.collector)
            dwc.recordedBy = output.collector
        if (output.notes)
            dwc.occurrenceRemarks = output.notes
        else if (output.eventNotes)
            dwc.occurrenceRemarks = output.eventNotes

        // map species info
        def species = model.find { it.dataType == "species" }
        if (species) dwc.scientificName = output[species.name].name

        // process exlpicit mappings
        model.each {
            def dwcName = it.darwinCore
            if (dwcName) {
                def val = output[it.name]
                if (val) dwc[dwcName] = val
            }
        }

        // determine potential subtree for recursive record generation
        def subtree = model.find { it.dataType == "list" && it.darwinCore }
        if (subtree) {
            output = output[subtree.name]
            if (output && output[0] instanceof Object) {
                model = subtree.columns
                output.each {
                    exportOutputTree(csvWriter, dwc.clone(), it, model)
                }
                return
            }
        }

        // only emit if there is a valid scientificName
        if (!dwc.scientificName || dwc.scientificName.size() == 0) return

        // if no valid subtree was found, we are at a leaf node, so emit it
        csvWriter.writeNext(
                [
                        dwc.occurrenceID ?: "",
                        dwc.scientificName ?: "",
                        dwc.family ?: "",
                        dwc.kingdom ?: "",
                        dwc.decimalLatitude ?: "",
                        dwc.decimalLongitude ?: "",
                        dwc.eventDate ?: "",
                        dwc.userId ?: "",
                        dwc.recordedBy ?: "",
                        dwc.usingReverseGeocodedLocality ?: "",
                        dwc.individualCount ?: "",
                        dwc.submissionMethod ?: "",
                        dwc.georeferenceProtocol ?: "",
                        dwc.identificationVerificationStatus ?: "",
                        dwc.occurrenceRemarks ?: "",
                        dwc.coordinateUncertaintyInMeters ?: "",
                        dwc.geodeticDatum ?: "",
                        dwc.imageLicence ?: "",
                        dwc.locality ?: "",
                        dwc.multimedia ? dwc.multimedia.collect { it.identifier }.join(";") : "",
                        dwc.modified ?: "",
                        dwc.locationID ?: ""
                ] as String[]
        )
    }

    /*
    * Parse species name and get species name.
    * (Use guid once bie new index is in place)
    * (Refactor BioCollect autocomplete to store both scientific and common name.)
    *
    * */

    public String getSpeciesName(record, projectActivity) {
        String name = ''
        if (record && projectActivity) {
            name = record.name
            switch (projectActivity?.species?.speciesDisplayFormat) {
                case 'SCIENTIFICNAME(COMMONNAME)':
                    List tokens = record.name ? record.name?.tokenize('(') : []
                    if (tokens && tokens.size() == 2) {
                        name = tokens.get(0)?.trim()
                    } else if (tokens && tokens.size() > 2) {
                        String find = tokens.get(tokens.size() - 1)
                        String modified = record.name?.replace(find, "")?.trim()
                        name = modified?.length() > 2 ? modified?.substring(0, modified.length() - 2) : modified
                    } else {
                        name = record.name
                    }
                    break
                case 'COMMONNAME(SCIENTIFICNAME)':
                    List tokens = record.name ? record.name?.tokenize('(') : []
                    name = tokens ? tokens.get(0)?.trim() : record.name
                    break
                case 'SCIENTIFICNAME':
                case 'COMMONNAME':
                default:
                    name = record.name
                    break
            }
        }

        name
    }

    /**
     * Event date has a variety of standards. This will try and convert it into Date object.
     * @param eventDate
     * @return
     */
    Date parseDate(String eventDate) {
        Date date
        try {
            date = DateUtils.parseDate(eventDate, ["yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", "yyyy-MM-dd'T'HH:mm:ssXXX", "yyyy-MM-dd'T'HH:mm:ssXX", "yyyy-MM-dd'T'HH:mm:ssX", "dd-MM-yyyy"] as String[])
        } catch (Exception pe) {
            log.error("Error parsing date ${eventDate}")
        }

        date
    }

    /**
     * Get license for a record by looking up license from project activity or return default license
     * @param record
     * @return
     */
    String getLicense(Map record) {
        if (record.projectActivityId) {
            Map projectActivity = projectActivityService.get(record.projectActvityId)
            if (projectActivity.dataSharingLicense) {
                return projectActivity.dataSharingLicense
            }
        }

        return grailsApplication.config.getProperty('license.default');
    }

    /**
     * regenerate records for all BioCollect projects
     * @return
     */
    def regenerateRecordsForBioCollectProjects() {
        task {
            // prevent simultaneous record generation when clicked multiple times.
            synchronized (LOCK_1) {
                Project.withNewSession { session ->
                    int projectMax = Holders.grailsApplication.config?.getProperty('records.project.max', Integer, 20)
                    def pagination = [
                            max   : projectMax,
                            offset: 0,
                            arrange: [
                                    order : 'desc',
                                    sort  : 'lastUpdated'
                            ],
                            searchCriteria: [
                                    isMERIT: false,
                                    isExternal: false,
                                    status: [ACTIVE]
                            ]
                    ]

                    int counter = 1
                    def projects = projectService.listProjects(pagination)
                    int total = projects.total
                    while (projects?.list) {
                        projects.list.each { Project project ->
                            log.info("Starting project ${project.name} ${project.projectId} number ${counter++} of ${total}")
                            regenerateRecordsForProject(project)
                        }

                        session.clear()
                        pagination.offset += pagination.max
                        projects = projectService.listProjects(pagination)
                    }
                }
            }
        }
        .onComplete {
            log.info("Record regeneration task completed")
        }
        .onError { Throwable error ->
            log.info("Record regeneration task stopped with an error", error)
        }
    }

    /**
     * Update or create darwin core records for activities in a project.
     * @param project
     * @param counter
     * @param total
     * @param session
     * @return
     */
    public void regenerateRecordsForProject(def project) {
        String projectId = project.projectId
        int activityMax = Holders.grailsApplication.config?.getProperty('records.activity.max', Integer, 20)
        Map activityParams = [
                max    : activityMax,
                offset : 0,
                sort: 'id',
                order: 'desc'
        ]

        Map searchCriteria = [
                projectId: projectId
        ]

        List activities = activityService.searchAndListActivityDomainObjects(searchCriteria, null, null, null, activityParams)

        while (activities) {
            activities?.parallelStream().forEach({ Activity activity ->
                regenerateRecordsForActivity(activity)
            })

            if (activityParams.offset % 100 == 0) {
                log.info("Fetching activities from offset ${activityParams.offset} of project ${project.name} ${project.projectId} ")
                Activity.withSession { session -> session.clear() }
            }

            activityParams.offset += activityParams.max
            activities = activityService.searchAndListActivityDomainObjects(searchCriteria, null, null, null, activityParams)
        }
    }

    /**
     * Update or create darwin core records for species in an activity.
     * @param activity
     * @return
     */
    public void regenerateRecordsForActivity(Activity activity) {
        String activityId = activity.activityId
        Output.withNewSession { outputSession ->
            Map params = [query: [activityId: activityId]]
            Map outputs = outputService.list(params)

            outputs?.list?.each { Output output ->
                try {
                    regenerateRecordsForOutput(output, activity, true)
                }
                catch (Exception e) {
                    log.error("Exception during processing of output - ${output?.outputId}", e)
                }
            }
        }
    }

    /**
     * Update or create darwin core records for species in an output.
     * @param output
     * @param activity
     */
    public void regenerateRecordsForOutput(Output output, Activity activity, boolean doNotAlert = false) {
        String outputId = output?.outputId
        Map props = outputService.toMap(output)
        outputService.createOrUpdateRecordsForOutput(activity, output, props, doNotAlert)

        // The createOrUpdateRecordsForOutput method can assign outputSpeciesIds so we need to check if
        // the output has changed.
        Map before = null
        Output.withNewSession {
            before = outputService.toMap(Output.findByOutputId(outputId))
        }
        if (props != before) {
            commonService.updateProperties(output, props)
        }
    }

    /** format species by specific type **/
    String formatTaxonName (Map data, String displayType) {
        String name = ''
        switch (displayType){
            case COMMON_NAME_SCIENTIFIC_NAME:
                if (data.commonName && data.scientificName) {
                    name = "${data.commonName} (${data.scientificName})"
                } else if (data.commonName) {
                    name = data.commonName
                } else if (data.scientificName) {
                    name = data.scientificName
                }
                break
            case SCIENTIFIC_NAME_COMMON_NAME:
                if (data.scientificName && data.commonName) {
                    name = "${data.scientificName} (${data.commonName})"
                } else if (data.scientificName) {
                    name = data.scientificName
                } else if (data.commonName) {
                    name = data.commonName
                }
                break
            case COMMON_NAME:
                name = data.commonName ?: data.scientificName ?: ""
                break
            case SCIENTIFIC_NAME:
                name = data.scientificName ?: ""
                break
        }

        name
    }
}
