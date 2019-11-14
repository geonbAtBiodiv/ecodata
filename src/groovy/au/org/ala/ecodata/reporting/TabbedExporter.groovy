package au.org.ala.ecodata.reporting

import au.org.ala.ecodata.ActivityForm
import au.org.ala.ecodata.ActivityFormService
import au.org.ala.ecodata.FormSection
import au.org.ala.ecodata.MetadataService
import au.org.ala.ecodata.Report
import au.org.ala.ecodata.ReportingService
import au.org.ala.ecodata.UserService
import au.org.ala.ecodata.metadata.OutputDataPropertiesBuilder
import au.org.ala.ecodata.metadata.OutputMetadata
import au.org.ala.ecodata.metadata.OutputModelProcessor
import grails.converters.JSON
import grails.util.Holders
import pl.touk.excel.export.getters.PropertyGetter
import pl.touk.excel.export.multisheet.AdditionalSheet


import java.text.SimpleDateFormat

/**
 * Basic support for exporting data based on a selection of content.
 */
class TabbedExporter {


    MetadataService metadataService = Holders.grailsApplication.mainContext.getBean("metadataService")
    UserService userService = Holders.grailsApplication.mainContext.getBean("userService")
    ReportingService reportingService =  Holders.grailsApplication.mainContext.getBean("reportingService")
    ActivityFormService activityFormService = Holders.grailsApplication.mainContext.getBean("activityFormService")
    OutputModelProcessor processor = new OutputModelProcessor()

    static String DATE_CELL_FORMAT = "dd/MM/yyyy"
    Map<String, AdditionalSheet> sheets
    List<String> tabsToExport
    XlsExporter exporter
    Map<String, Object> documentMap
    TimeZone timeZone
    // These fields map full activity names to shortened names that are compatible with Excel tabs.
    protected Map<String, String> activitySheetNames = [:]
    protected Map<String, List<AdditionalSheet>> typedActivitySheets = [:]

    TabbedExporter(XlsExporter exporter, List<String> tabsToExport = [], Map<String, Object> documentMap = [:], TimeZone timeZone = TimeZone.default) {
        this.exporter = exporter
        this.sheets = new HashMap<String, AdditionalSheet>()
        this.tabsToExport = tabsToExport != null ? tabsToExport : []
        this.documentMap = documentMap
        this.timeZone = timeZone
        exporter.setDateCellFormat(DATE_CELL_FORMAT)
    }

    public setDateFormat(String dateFormat) {
        exporter.setDateCellFormat(dateFormat)
    }

    boolean  shouldExport(String sheetName) {
        return !tabsToExport || tabsToExport.contains(sheetName)
    }

    protected AdditionalSheet getSheet(String name, List<String> headers) {
        if (!sheets[name]) {
            sheets[name] = exporter.addSheet(name, headers)
        }
        sheets[name]
    }

    @Deprecated
    protected Map outputProperties(name) {
        def model = metadataService.annotatedOutputDataModel(name)
        def headers = []
        def properties = []
        model.each {
            if (it.dataType == 'list') {
                it.columns.each { col ->
                    properties << it.name + '.' + col.name
                    headers << col.label
                }
            } else if (it.dataType in ['photoPoints', 'matrix', 'masterDetail']) {
                // not supported, do nothing.
            } else if (it.dataType == 'stringList') {
                if (it.constraints) {
                    it.constraints.each { constraint ->
                        headers << it.description + ' - ' + constraint
                        properties << it.name + '['+constraint+']'
                    }

                }
                else {
                    properties << it.name
                    headers << it.label ?: it.description
                }
            }
            else {
                properties << it.name
                headers << it.label ?: it.description
            }
        }
        List propertyGetters = properties.collect { new OutputDataPropertiesBuilder(it, model, documentMap, timeZone) }
        [headers: headers, propertyGetters: propertyGetters]
    }
    /**
     *
     * @param outputModel OutputModel generated from sectionForm->template
     * @return
     */

    protected Map buildOutputProperties(OutputMetadata outputModel) {

        List annotateDataModel = outputModel.annotateDataModel()

        def headers = []
        def properties = []

        annotateDataModel.each {
            if (it.dataType == 'list') {
                it.columns.each { col ->
                    properties << it.name + '.' + col.name
                    headers << col.label
                }
            } else if (it.dataType in ['photoPoints', 'matrix', 'masterDetail']) {
                // not supported, do nothing.
            } else if (it.dataType == 'stringList') {
                if (it.constraints) {
                    it.constraints.each { constraint ->
                        headers << it.description + ' - ' + constraint
                        properties << it.name + '[' + constraint + ']'
                    }

                } else {
                    properties << it.name
                    headers << it.label ?: it.description
                }
            } else {
                properties << it.name
                headers << it.label ?: it.description
            }
        }

        def propertyGetters = properties.collect {
            new OutputDataPropertiesBuilder(it, annotateDataModel, documentMap, timeZone)
        }

        [headers: headers, propertyGetters: propertyGetters]
    }

    /**
     *Flatten output data + common data
     *
     * @param outputModel
     * @param output
     * @param commonData
     * @return
     */
    @Deprecated
    private List getOutputData(OutputMetadata  outputModel, Map output, Map commonData) {
        List flatData = []
        if (output) {
            flatData = processor.flatten(output, outputModel, false)
            flatData = flatData.collect { commonData + it }
        }
        flatData
    }

    /**
     * Flatten output data only
     *
     * @param outputModel
     * @param output
     * @return
     */
    private List getOutputData(OutputMetadata  outputModel, Map output) {
        List flatData = []
        if (output) {
            flatData = processor.flatten(output, outputModel, false)
        }
        flatData
    }


    /**
     * Generate data model of a given output type from activity for excel sheet, if outputname is given
     * Otherwise generate data models of all outputs
     *
     * including, headers, data cell reader and data itself
     * @param activity
     * @outputName  About the output name
     * @return  Sheet headers, Getter of data model, data itself
     */
    protected buildOutputSheetData(Map activity,String outputName=null){

        String activityType = activity.type
        Integer formVersion = activity.formVersion
        ActivityForm activityForm = activityFormService.findActivityForm(activityType, formVersion)

        List outputGetters = []
        List headers = []
        List outputData = []

        activity.outputs.each{ output->
            if ( !outputName || outputName == output.name )  {
                FormSection formSection = activityForm?.getFormSection(output.name)
                if(formSection && formSection.template){

                    OutputMetadata outputModel = new OutputMetadata(formSection.template)

                    Map outputProperty = buildOutputProperties(outputModel)
                    outputGetters += outputProperty.propertyGetters
                    headers += outputProperty.headers

                    outputData += getOutputData(outputModel, output)
                }else{
                    log.error("Cannot find template of " + output.name)
                }
            }
        }
        return [headers: headers, getters: outputGetters, data: outputData]
    }

    /**
     *
     * These fields map full activity names to shortened names that are compatible with Excel tabs.
     * If it has the tab already, create a new tab with index
     *
     * @param sheetName
     * @param headers
     * @return
     */
    protected AdditionalSheet createSheet(String sheetName, List headers) {

        if (!typedActivitySheets[sheetName]) {
            String name = XlsExporter.sheetName(sheetName)

            // If the sheets are named similarly, they may end up the same after being changed to excel
            // tab compatible strings
            int i = 1
            while (activitySheetNames[sheetName]) {
                sheetName = sheetName.substring(0, name.length()-1)
                sheetName = sheetName + Integer.toString(i)
            }

            activitySheetNames[sheetName] = sheetName
            typedActivitySheets[sheetName] = exporter.addSheet(name, headers)
        }
        typedActivitySheets[sheetName]
    }

    protected AdditionalSheet createEmptySheet(String sheetName){
        createSheet(sheetName,['No data'])
    }


    protected void exportReports(AdditionalSheet sheet, Map entity, List<String> reportProperties) {
        int row = sheet.getSheet().lastRowNum
        SimpleDateFormat format = new SimpleDateFormat(DATE_CELL_FORMAT)
        List data = []
        entity.reports?.each { report ->
            Map statusCounts = [:].withDefault { 1 }
            Map previousChange = null
            report.statusChangeHistory?.eachWithIndex { change, i ->
                String statusChange = change.status
                if (change.category) {
                    statusChange = change.category + ' ' + change.status
                }
                int count = statusCounts[statusChange]
                statusCounts[change.status] = count + 1
                String noTimeStr = format.format(change.dateChanged)
                Date noTime = format.parse(noTimeStr)
                int delta = previousChange ? Report.weekDaysBetween(previousChange.dateChanged, change.dateChanged) : 0
                previousChange = entity + [reportName: report.name, fromDate: report.fromDate, toDate: report.toDate, progress:report.progress, reportStatus: statusChange + " " + count, changedBy: change.changedBy, dateChanged: noTime, delta: delta, comment: change.comment]
                data << previousChange
            }
        }
        sheet.add(data, reportProperties, row + 1)
    }

    protected void exportReportSummary(AdditionalSheet sheet, Map entity, List<String> reportSummaryProperties) {
        int row = sheet.getSheet().lastRowNum
        SimpleDateFormat format = new SimpleDateFormat(DATE_CELL_FORMAT)
        List data = []
        entity.reports?.each { report ->

            Map reportDetails = entity + [reportName:report.name, fromDate:report.fromDate, toDate:report.toDate, progress:report.progress]
            reportDetails.activityCount = reportingService.getActivityCountForReport(report)
            if (report.statusChangeHistory) {
                int numChanges = report.statusChangeHistory.size()
                def change = report.statusChangeHistory[numChanges-1]
                String noTimeStr = format.format(change.dateChanged)
                Date noTime = format.parse(noTimeStr)
                int delta = 0
                if (numChanges > 1) {
                    def previousChange = report.statusChangeHistory[numChanges-2]
                    delta = Report.weekDaysBetween(previousChange.dateChanged, change.dateChanged)

                }
                reportDetails.reportStatus = change.status
                reportDetails.changedBy = change.changedBy
                if (change.changedBy) {
                    reportDetails.changedByName = userService.lookupUserDetails(change.changedBy).displayName
                }
                reportDetails.dateChanged = noTime
                reportDetails.delta = delta

                data << reportDetails
            }
            else if (report.toDate <= new Date()) {
                reportDetails.reportStatus = 'Unpublished (no action – never been submitted)'
                reportDetails.delta = 0

                data << reportDetails
            }
        }
        sheet.add(data, reportSummaryProperties, row + 1)
    }

    protected void exportList(String tab, Map project, List data, List headers, List properties) {
        if (shouldExport(tab) && data) {
            AdditionalSheet sheet = getSheet(tab, headers)
            int row = sheet.getSheet().lastRowNum
            List augmentedList = data?.collect {
                it.putAll(project)
                it
            }
            sheet.add(augmentedList, properties, row+1)
        }
    }

    static class LengthLimitedGetter extends PropertyGetter<String, String> {
        /** Excel cells can hold a maximum of 32767 characters */
        static final int MAX_CELL_LENGTH = 32767

        LengthLimitedGetter(String propertyName) {
            super(propertyName)
        }
        String format(String value) {
            if (value && value.length() > MAX_CELL_LENGTH) {
                value = value.substring(0, MAX_CELL_LENGTH)
            }
            return value
        }
    }

    static class StringToDoublePropertyGetter extends PropertyGetter<Object, Number> {

        StringToDoublePropertyGetter(String propertyName) {
            super(propertyName)
        }

        @Override
        protected format(Object value) {
            try {
                return Double.parseDouble(value?.toString())
            }
            catch (NumberFormatException e) {
                return null
            }
        }
    }
}
