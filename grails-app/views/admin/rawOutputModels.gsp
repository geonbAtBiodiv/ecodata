<%@ page import="org.apache.commons.lang.StringEscapeUtils" %>
<!doctype html>
<html>
    <head>
        <meta name="layout" content="adminLayout"/>
        <title>Output models | Admin | Data capture | Atlas of Living Australia</title>
        <script>
            var fcConfig = {
                activityModelUpdateUrl:"${createLink(controller:'activityForm', action:'update')}",
                outputDataModelUrl: "${createLink(action: 'getOutputDataModel')}",
                getActivityFormUrl: "${createLink(controller:'activityForm', action:'get')}"
            };
        </script>

    </head>

    <body>
        <content tag="pageTitle">Output models</content>
        <content tag="adminButtonBar">
            <button type="button" id="btnSave" data-bind="click:save" class="btn btn-success">Save</button>
            <button type="button" data-bind="click:revert" class="btn">Cancel</button>
        </content>
        <div class="row-fluid form-selection">
            <div class="span6">
                <label>Activity form: <select class="span12" name="formSelector" data-bind="options:activityForms, optionsCaption:'Select a form to edit', optionsText:'name', value:selectedFormName"></select></label>
            </div>
            <div class="span6">
                <label>Version:<br/> <select class="span3" name="versionSelector" data-bind="options:activityFormVersions, value:selectedFormVersion"></select></label>
            </div>
        </div>
        <div>
            <div class="span6">
                <label>Form section: <select class="span12" name="outputSelector" data-bind="options:selectedActivityForm()?selectedActivityForm().sections:[], optionsText:'name', optionsCaption:'Select an section to edit', value:selectedFormSection"></select></label>
            </div>

        </div>

        <div class="row-fluid">
            <div class="span12"><h2 data-bind="text:modelName"></h2></div>
        </div>
        <div class="row-fluid">
            <div class="alert" data-bind="visible:hasMessage">
                <button type="button" class="close" data-dismiss="alert">&times;</button>
                <strong>Warning!</strong> <span data-bind="text:message"></span>
            </div>
        </div>
        <div class="row-fluid">
            <div class="span12">
                <textarea id="outputModelEdit" style="width:97%;min-height:600px;"></textarea>
            </div>
        </div>




<asset:script>
    $(function(){

        var forms = JSON.parse('${(availableActivities as grails.converters.JSON).toString()}');
        var viewModel = new EditActivityFormSectionViewModel(forms, fcConfig);
        ko.applyBindings(viewModel);

        $('select').select2();
    });
</asset:script>
        </body>
</html>