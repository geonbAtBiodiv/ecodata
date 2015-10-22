package au.org.ala.ecodata

import au.org.ala.web.AuthService
import grails.transaction.Transactional
import org.bson.BSONObject

class CommentService {
    UserService userService
    PermissionService permissionService
    ActivityService activityService
    AuthService authService
    def grailsApplication

    /**
     * get domain object properties. This is useful when converting object to json. mainly used to exclude
     * inheritted properties of domain objects when convert object to json.
     * @param it
     * @return
     */
    Map getPropertiesOfDomainObject(Comment it) {
        BSONObject dbo = it.getProperty("dbo")
        Map mapOfProperties = dbo.toMap()
        mapOfProperties.id = mapOfProperties._id
        mapOfProperties.remove("_id")
        mapOfProperties
    }

    /**
     * A recursive method to get a comment and its children properties.
     * it also does a lookup for user name using userId.
     * @param c
     * @return
     */
    Map getCommentProperties (Comment c){
        Map comment;
        comment = getPropertiesOfDomainObject(c)
        comment.displayName = userService.lookupUserDetails(c.userId)?.displayName;
        if(c.children?.size() > 0){
            comment.children = []
            c.children.each{
                comment.children.add(getCommentProperties(it))
            }
        }
        comment
    }

    /**
     * sort children comment using the current sort order. It is a recursive function.
     * @param comments
     * @param order
     * @return
     */
    List sortCommentChildren(List comments, Boolean order){
        comments.sort(true, {it.dateCreated})
        // reverse list if sorting has to be done in reverse order
        if(!order){
            comments.reverse(true)
        }

        comments.each { comment ->
            if(comment.children?.size()){
                sortCommentChildren(comment.children, order);
            }
        }

        comments
    }

    /**
     * create an object also modifies its parent.
     * @param json
     * @return
     */
    @Transactional
    Comment create(Object json){
        Comment newComment = new Comment(json)
        Comment parent;
        if (newComment.dateCreated == null) {
            newComment.dateCreated = new Date();
        }

        Comment comment = newComment.save(true)

        if (json.parent) {
            parent = Comment.get(json.parent);
            if (parent) {
                comment.parent = parent;
                parent.children.add(comment);
                parent.save(true);
                comment.save(true);
            }
        }
        comment
    }

    /**
     * update a comment
     * @param json
     * @return
     */
    @Transactional
    Comment update(Object json){
        Boolean update = false
        Comment comment = Comment.get(json.id);
        if (comment) {
            if (comment.userId == json.userId) {
                update = true;
            }  else if(canUserEditOrDeleteComment(json.userId, json.entityId, json.entityType) || json.isALAAdmin){
                update = true;
            }

            if(update){
                comment.text = json.text;
                //update time
                comment.dateCreated = new Date();
                comment.save(flush: true)
            }
        }

        comment
    }

    @Transactional
    Comment delete(Map params) {
        Comment comment = Comment.get(params.id);
        if (comment) {
            if (comment.userId == params.userId) {
                comment.delete(flush: true);
            } else if(canUserEditOrDeleteComment(params.userId, params.entityId, params.entityType) || params.isALAAdmin){
                comment.delete(flush: true);
            }
        }

        comment
    }

    /**
     * checks if a user is admin in project or ala admin.
     * This is necessary since admin can delete / modify other's comment(s).
     * @param userId
     * @param entityId
     * @param entityType
     * @return
     */
    Boolean canUserEditOrDeleteComment(String userId, String entityId, String entityType){

        Boolean admin = false;
        switch (entityType){
            case 'au.org.ala.ecodata.Activity':
                admin = permissionService.isUserAdminForProject(userId, getProjectIdFromActivityId(entityId));
                break;
        }

        admin
    }

    /**
     * get project id from activity record
     * @param id
     * @return
     */
    String getProjectIdFromActivityId(String id){
        Map activity = activityService.get(id)
        activity?.projectId
    }
}
