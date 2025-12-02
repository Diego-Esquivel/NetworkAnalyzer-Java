package com.filters.read_filters.tcp;

abstract class ReadFilter {
    protected static String description;
    protected static String filterExpression;

    public static String getDescription() {
        return description;
    }

    public static String getFilterExpression() {
        return filterExpression;
    }
}
