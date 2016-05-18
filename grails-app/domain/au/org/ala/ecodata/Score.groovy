package au.org.ala.ecodata

class Score {

    String scoreId

    /** Enumerates the currently supported ways to aggregate output scores. */
    enum AGGREGATION_TYPE {SUM, AVERAGE, COUNT, HISTOGRAM, SET}

    /** The name of the output to which the score belongs */
    String outputName

    /** The name of the score (as defined in the OutputModel */
    String name

    String category

    String listName

    String groupBy

    /** In the case that a groupBy term is specified, the filterBy term will select the value from a particular group */
    String filterBy

    /** "piechart" or "barchart" only currently */
    String displayType

    /** Defines how this score should be aggregated */
    AGGREGATION_TYPE aggregationType

    /** The label for this score when displayed */
    String label

    /** A more detailed description of the score and how it should be interpreted */
    String description

    /** Whether or not this score is suitable for use as a project output target */
    boolean isOutputTarget

    /** Used for mapping this score to the GMS */
    String gmsId

    /**
     * The units this score is measured in.  May not make sense for all scores or for an aggregrated result
     * (e.g. units don't make sense for a count based aggregation).
     */
    String units


    static constraints = {
    }

    static mapping = {
        scoreId index: true
        version false
    }

    def beforeValidate() {
        if (scoreId == null) {
            scoreId = Identifiers.getNew(true, "")
        }
    }
}