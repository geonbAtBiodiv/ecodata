package au.org.ala.ecodata.graphql.enums

enum DateRange {

    Jul_2011_Jan_2012("2011-07-01", "2012-01-01"),
    Jan_2012_Jul_2012("2012-01-01", "2012-07-01"),
    Jul_2012_Jan_2013("2012-07-01", "2013-01-01"),
    Jan_2013_Jul_2013("2013-07-01", "2013-01-01"),
    Jul_2013_Jan_2014("2013-07-01", "2014-01-01"),
    Jan_2014_Jul_2014("2014-07-01", "2014-01-01"),
    Jul_2014_Jan_2015("2014-07-01", "2015-01-01"),
    Jan_2015_Jul_2015("2015-07-01", "2015-01-01"),
    Jul_2015_Jan_2016("2015-07-01", "2016-01-01"),
    Jan_2016_Jul_2016("2016-07-01", "2016-01-01"),
    Jul_2016_Jan_2017("2016-07-01", "2017-01-01"),
    Jan_2017_Jul_2017("2017-07-01", "2017-01-01"),
    Jul_2017_Jan_2018("2017-07-01", "2018-01-01"),
    Jan_2018_Jul_2018("2018-07-01", "2018-01-01"),
    Jul_2018_Jan_2019("2018-07-01", "2019-01-01"),
    Jan_2019_Jul_2019("2019-07-01", "2019-01-01"),
    Jul_2019_Jan_2020("2019-07-01", "2020-01-01"),
    Jan_2020_Jul_2020("2020-07-01", "2020-01-01"),
    Jul_2020_Jan_2021("2020-07-01", "2021-01-01")


    private String from
    private String to
    private DateRange(String fromDate, String toDate) {
        from = fromDate
        to = toDate
    }

    String getFromDate() {
        return from
    }

    String getToDate() {
        return to
    }
}