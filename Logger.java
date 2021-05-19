
package com.zhbi.socksproxysever;

import java.util.Date;


class Logger {
    static boolean debug = true;

    static final int FILE_STACK_DEPTH = 3;
    static final int CLASS_STACK_DEPTH = 2;
    static final int METHOD_STACK_DEPTH = 3;
    static final int LINE_STACK_DEPTH = 3;

    static final String TIME_FORMAT = "%1$tF %1$tT";
    static final String LOG_FORMAT = "[%04d] %s %s %s %d %s(): %s\n";

    static int logNumber = 1;

    public static void logger(String fmt, Object... args) {
        if (debug == false) {
            return;
        }

        String logs = null;
        logs = String.format(fmt, args);
        System.out.print(logs);
    }

    public static String localDateTime() {
        Date date = new Date();
        String dateTime = String.format(TIME_FORMAT, date);
        return dateTime;
    }

    public static String fileName() {
        return(Thread.currentThread()
                .getStackTrace()[FILE_STACK_DEPTH].getFileName());
    }

    public static String className() {
        return(Thread.currentThread()
                .getStackTrace()[CLASS_STACK_DEPTH].getClassName());
    }

    public static String methodName() {
        return(Thread.currentThread()
                .getStackTrace()[METHOD_STACK_DEPTH].getMethodName());
    }

    public static int lineNumber() {
        return(Thread.currentThread()
                .getStackTrace()[LINE_STACK_DEPTH].getLineNumber());
    }

    public static void info(String fmt, Object... info) {
        logger(LOG_FORMAT, logNumber, "INFO:",
            localDateTime(), fileName(), lineNumber(), methodName(),
            String.format(fmt, info));

        logNumber++;
    }

    public static void warn(String fmt, Object... warn) {
        logger(LOG_FORMAT, logNumber, "WARN:",
            localDateTime(), fileName(), lineNumber(), methodName(),
            String.format(fmt, warn));

        logNumber++;
    }

    public static void error(String fmt, Object... err) {
        logger(LOG_FORMAT, logNumber, "ERROR:",
            localDateTime(), fileName(), lineNumber(), methodName(),
            String.format(fmt, err));

        logNumber++;
    }
}
