package au.org.ala.ecodata

import spock.lang.Specification

class EmbargoUtilSpec extends Specification {

    def "EmbargoOption NONE should result in a null embargoUntil date"() {
        setup:
        ProjectActivity activity = new ProjectActivity(embargoOption: EmbargoOption.NONE)

        when:
        Date embargoUntil = EmbargoUtil.calculateEmbargoUntilDate(activity)

        then:
        embargoUntil == null
    }

    def "EmbargoOption DAYS should add the number of days to the current date"() {
        setup:
        ProjectActivity activity = new ProjectActivity(embargoOption: EmbargoOption.DAYS, embargoForDays: 10)

        when:
        Date embargoUntil = EmbargoUtil.calculateEmbargoUntilDate(activity)

        then:
        Calendar output = Calendar.getInstance()
        output.add(Calendar.DATE, 10)
        output.set(Calendar.HOUR_OF_DAY, 0)
        output.set(Calendar.MINUTE, 0)
        output.set(Calendar.SECOND, 0)
        output.set(Calendar.MILLISECOND, 0)
        embargoUntil == output.getTime()
    }

    def "EmbargoOption DATE should return the requested embargoUntil date"() {
        setup:
        Calendar input = Calendar.getInstance()
        input.add(Calendar.MONTH, 4)
        ProjectActivity activity = new ProjectActivity(embargoOption: EmbargoOption.DATE, embargoUntil: input.getTime())

        when:
        Date embargoUntil = EmbargoUtil.calculateEmbargoUntilDate(activity)

        then:
        Calendar output = Calendar.getInstance()
        output.add(Calendar.MONTH, 4)
        output.set(Calendar.HOUR_OF_DAY, 0)
        output.set(Calendar.MINUTE, 0)
        output.set(Calendar.SECOND, 0)
        output.set(Calendar.MILLISECOND, 0)
        embargoUntil == output.getTime()
    }

    def "The calculated embargoUntil date cannot be more than 12 months in the future"() {
        setup:
        ProjectActivity activity = new ProjectActivity(embargoOption: EmbargoOption.DATE, embargoUntil: new Date(2020, 10, 9))

        when:
        EmbargoUtil.calculateEmbargoUntilDate(activity)

        then:
        thrown IllegalArgumentException
    }

    def "The calculated embargoUntil date cannot be in the past"() {
        setup:
        ProjectActivity activity = new ProjectActivity(embargoOption: EmbargoOption.DATE, embargoUntil: new Date(2010, 10, 9))

        when:
        EmbargoUtil.calculateEmbargoUntilDate(activity)

        then:
        thrown IllegalArgumentException
    }
}
